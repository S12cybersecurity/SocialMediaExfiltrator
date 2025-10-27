#include <windows.h>
#include <winhttp.h>
#include <string>
#include <vector>
#include <iostream>

#pragma comment(lib, "winhttp.lib")

// Convert wide string (UTF-16) to UTF-8 std::string
std::string wstring_to_utf8(const std::wstring& ws) {
    if (ws.empty()) return {};
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, ws.data(), (int)ws.size(), NULL, 0, NULL, NULL);
    std::string s(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, ws.data(), (int)ws.size(), &s[0], size_needed, NULL, NULL);
    return s;
}

// Percent-encode bytes for application/x-www-form-urlencoded
std::string url_encode(const std::string& s) {
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    out.reserve(s.size() * 3);
    for (unsigned char c : s) {
        // unreserved characters according to RFC3986: ALPHA / DIGIT / "-" / "." / "_" / "~"
        if ((c >= '0' && c <= '9') ||
            (c >= 'A' && c <= 'Z') ||
            (c >= 'a' && c <= 'z') ||
            c == '-' || c == '.' || c == '_' || c == '~') {
            out.push_back((char)c);
        }
        else if (c == ' ') {
            out.push_back('+'); // application/x-www-form-urlencoded uses +
        }
        else {
            out.push_back('%');
            out.push_back(hex[c >> 4]);
            out.push_back(hex[c & 0xF]);
        }
    }
    return out;
}

bool sendTelegramMessage(const std::wstring& token, const std::wstring& chat_id, const std::wstring& text) {
    const std::wstring host = L"api.telegram.org";
    // path: /bot<token>/sendMessage
    std::wstring path = L"/bot" + token + L"/sendMessage";

    // Prepare body: chat_id=...&text=...
    std::string utf8_chat = wstring_to_utf8(chat_id);
    std::string utf8_text = wstring_to_utf8(text);
    std::string body = "chat_id=" + url_encode(utf8_chat) + "&text=" + url_encode(utf8_text);

    HINTERNET hSession = WinHttpOpen(L"WinHTTP-Telegram-Sender/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        std::cerr << "WinHttpOpen failed: " << GetLastError() << "\n";
        return false;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        std::cerr << "WinHttpConnect failed: " << GetLastError() << "\n";
        WinHttpCloseHandle(hSession);
        return false;
    }

    // OpenRequest: POST, secure
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", path.c_str(),
        NULL, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        std::cerr << "WinHttpOpenRequest failed: " << GetLastError() << "\n";
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    // Optional: set TLS validation flags if needed (default behavior validates certs).
    // Example to ignore cert errors (NOT recommended for production):
    // DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
    // WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));

    // Headers
    LPCWSTR headers = L"Content-Type: application/x-www-form-urlencoded";
    BOOL bResult = WinHttpSendRequest(hRequest,
        headers, (DWORD)wcslen(headers),
        (LPVOID)body.data(), (DWORD)body.size(),
        (DWORD)body.size(),
        0);
    if (!bResult) {
        std::cerr << "WinHttpSendRequest failed: " << GetLastError() << "\n";
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        std::cerr << "WinHttpReceiveResponse failed: " << GetLastError() << "\n";
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    // Read response (optional — Telegram returns JSON)
    DWORD bytesAvailable = 0;
    std::string response;
    while (WinHttpQueryDataAvailable(hRequest, &bytesAvailable) && bytesAvailable > 0) {
        std::vector<char> buffer(bytesAvailable + 1);
        DWORD bytesRead = 0;
        if (WinHttpReadData(hRequest, buffer.data(), bytesAvailable, &bytesRead) && bytesRead > 0) {
            response.append(buffer.data(), bytesRead);
        }
        else {
            break;
        }
    }

    // Clean up
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    // Print response for debugging
    std::cout << "Response:\n" << response << "\n";

    // A simple check: if response contains '"ok":true' it's success
    if (response.find("\"ok\":true") != std::string::npos) return true;
    return false;
}

std::wstring getFakePassword() {
    return L"FAKEPASSWORD";
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 3) {
        std::wcout << L"Usage: send_telegram_winhttp.exe <BOT_TOKEN> <CHAT_ID>\n";
        std::wcout << L"Example: send_telegram_winhttp.exe 123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11 987654321 \n";
        std::wcout << L"Note: group chat ids are negative numbers (e.g. -1001234567890).\n";
        return 1;
    }

    std::wstring token = argv[1];
    std::wstring chat_id = argv[2];

    std::wstring text = getFakePassword();

    bool ok = sendTelegramMessage(token, chat_id, text);
    if (ok) {
        std::wcout << L"Message sent successfully.\n";
        return 0;
    }
    else {
        std::wcout << L"Failed to send message. Check token/chat_id and network.\n";
        return 2;
    }
}
