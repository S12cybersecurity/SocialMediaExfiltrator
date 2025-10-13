#include <windows.h>
#include <winhttp.h>
#include <string>
#include <vector>
#include <iostream>

#pragma comment(lib, "winhttp.lib")

// Minimal JSON escaping for "content" field
std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (unsigned char c : s) {
        switch (c) {
        case '\"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (c < 0x20) {
                char buf[7];
                std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                out += buf;
            }
            else {
                out += static_cast<char>(c);
            }
        }
    }
    return out;
}

bool crack_url(const std::wstring& url, std::wstring& host, INTERNET_SCHEME& scheme,
    std::wstring& path, INTERNET_PORT& port) {
    URL_COMPONENTS uc{};
    uc.dwStructSize = sizeof(uc);

    // First call to get lengths
    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &uc)) return false;

    std::vector<wchar_t> host_buf(uc.dwHostNameLength + 1);
    std::vector<wchar_t> path_buf(uc.dwUrlPathLength + 1);

    uc.lpszHostName = host_buf.data();
    uc.dwHostNameLength = static_cast<DWORD>(host_buf.size());
    uc.lpszUrlPath = path_buf.data();
    uc.dwUrlPathLength = static_cast<DWORD>(path_buf.size());

    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &uc)) return false;

    host.assign(uc.lpszHostName, uc.dwHostNameLength);
    path.assign(uc.lpszUrlPath, uc.dwUrlPathLength);
    scheme = uc.nScheme;
    port = uc.nPort ? uc.nPort
        : (uc.nScheme == INTERNET_SCHEME_HTTPS ? INTERNET_DEFAULT_HTTPS_PORT
            : INTERNET_DEFAULT_HTTP_PORT);
    if (path.empty()) path = L"/";
    return true;
}

DWORD query_status_code(HINTERNET hRequest) {
    DWORD status = 0, size = sizeof(status);
    WinHttpQueryHeaders(hRequest,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &status, &size, WINHTTP_NO_HEADER_INDEX);
    return status;
}

bool query_retry_after_seconds(HINTERNET hRequest, DWORD& out_seconds) {
    // Retry-After can be seconds (number) or a date. We handle numeric seconds.
    DWORD size = 0;
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RETRY_AFTER, NULL, NULL, &size, NULL);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) return false;

    std::vector<wchar_t> buf(size / sizeof(wchar_t));
    if (!WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RETRY_AFTER, NULL, buf.data(), &size, NULL))
        return false;

    // Try to parse as integer seconds
    out_seconds = std::wcstoul(buf.data(), nullptr, 10);
    return out_seconds > 0;
}

bool send_discord_webhook(const std::wstring& webhook_url, const std::string& message, int max_retries = 2) {
    // Hardcode Discord webhook details
    std::wstring host = L"discord.com";
    std::wstring path = webhook_url; // Assume full path is passed or extract it manually
    INTERNET_SCHEME scheme = INTERNET_SCHEME_HTTPS;
    INTERNET_PORT port = INTERNET_DEFAULT_HTTPS_PORT;

    // If webhook_url contains full URL, extract just the path
    size_t pos = webhook_url.find(L"discord.com");
    if (pos != std::wstring::npos) {
        size_t path_start = webhook_url.find(L'/', pos + 11); // 11 = length of "discord.com"
        if (path_start != std::wstring::npos) {
            path = webhook_url.substr(path_start);
        }
    }

    // Prepare JSON payload (UTF-8)
    std::string payload = std::string("{\"content\":\"") + json_escape(message) + "\"}";

    HINTERNET hSession = WinHttpOpen(L"winhttp-discord/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) { std::cerr << "WinHttpOpen failed.\n"; return false; }

    // Optional timeouts (ms)
    WinHttpSetTimeouts(hSession, 5000, 5000, 10000, 10000);

    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), port, 0);
    if (!hConnect) {
        std::cerr << "WinHttpConnect failed.\n";
        WinHttpCloseHandle(hSession);
        return false;
    }

    DWORD flags = (scheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;

    bool success = false;
    int attempts = 0;
    while (attempts++ <= max_retries) {
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", path.c_str(),
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
        if (!hRequest) {
            std::cerr << "WinHttpOpenRequest failed.\n";
            break;
        }

        // For stricter TLS: disable insecure protocols if desired (optional)
        // DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
        // WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));

        // Headers
        LPCWSTR headers = L"Content-Type: application/json\r\n";
        BOOL ok = WinHttpSendRequest(hRequest,
            headers, -1L,
            (LPVOID)payload.data(),
            (DWORD)payload.size(),
            (DWORD)payload.size(),
            0);
        if (!ok) {
            std::cerr << "WinHttpSendRequest failed.\n";
            WinHttpCloseHandle(hRequest);
            break;
        }

        if (!WinHttpReceiveResponse(hRequest, NULL)) {
            std::cerr << "WinHttpReceiveResponse failed.\n";
            WinHttpCloseHandle(hRequest);
            break;
        }

        DWORD status = query_status_code(hRequest);
        if (status >= 200 && status < 300) {
            success = true;
            WinHttpCloseHandle(hRequest);
            break;
        }

        if (status == 429 && attempts <= max_retries) {
            DWORD retrySec = 0;
            if (query_retry_after_seconds(hRequest, retrySec) && retrySec <= 30) {
                std::cerr << "Rate limited (429). Retrying after " << retrySec << "s...\n";
                Sleep(retrySec * 1000);
            }
            else {
                std::cerr << "Rate limited (429). Retrying with default backoff 5s...\n";
                Sleep(5000);
            }
            WinHttpCloseHandle(hRequest);
            continue;
        }
        else {
            std::cerr << "HTTP error: " << status << "\n";
            WinHttpCloseHandle(hRequest);
            break;
        }
    }

    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return success;
}

std::wstring getFakePassword() {
    std::wstring fakePassword = L"FakePassword123!"; // Replace with your fake password
    return fakePassword;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        std::wcerr << L"Usage: " << argv[0] << L" <webhook_url>\n";
        return 1;
    }
    std::wstring webhook = argv[1];
    std::wstring message = getFakePassword();

    // Convert wide string (UTF-16) to UTF-8 for Discord
    int len = WideCharToMultiByte(CP_UTF8, 0, message.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string msg(len - 1, '\0'); // allocate len-1 chars

    // Use &msg[0] to get writable pointer
    WideCharToMultiByte(CP_UTF8, 0, message.c_str(), -1, &msg[0], len, nullptr, nullptr);

    bool ok = send_discord_webhook(webhook, msg);
    if (ok) {
        std::cout << "Message sent successfully!\n";
        return 0;
    }
    std::cerr << "Failed to send message.\n";
    return 2;
}