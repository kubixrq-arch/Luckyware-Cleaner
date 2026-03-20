#pragma once
// Luckyware Cleaner - Network Control Module
// Disconnects/Reconnects internet by disabling/enabling all active network adapters.
#include <windows.h>
#include <iphlpapi.h>
#include <shellapi.h>
#include <vector>
#include <string>
#include <iostream>
#include <algorithm>
#include "ui.hpp"
#include "lang.hpp"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "shell32.lib")

namespace Network {

using namespace UI;
using namespace Lang;

struct AdapterInfo {
    std::string name;
    std::wstring wname;
};

inline std::vector<AdapterInfo> get_active_adapters() {
    std::vector<AdapterInfo> adapters;
    ULONG outBufLen = 15000;
    PIP_ADAPTER_ADDRESSES pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);

    if (pAddresses == nullptr) return adapters;

    ULONG dwRetVal = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAddresses, &outBufLen);
    if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
        free(pAddresses);
        pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
        if (pAddresses == nullptr) return adapters;
        dwRetVal = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAddresses, &outBufLen);
    }

    if (dwRetVal == NO_ERROR) {
        PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses;
        while (pCurrAddresses) {
            // Only consider physical adapters that are up
            if (pCurrAddresses->IfType != IF_TYPE_SOFTWARE_LOOPBACK && 
                pCurrAddresses->OperStatus == IfOperStatusUp) {
                AdapterInfo info;
                info.wname = pCurrAddresses->FriendlyName;
                
                char nameBuf[MAX_PATH];
                WideCharToMultiByte(CP_UTF8, 0, pCurrAddresses->FriendlyName, -1, nameBuf, MAX_PATH, nullptr, nullptr);
                info.name = nameBuf;
                
                adapters.push_back(info);
            }
            pCurrAddresses = pCurrAddresses->Next;
        }
    }

    if (pAddresses) free(pAddresses);
    return adapters;
}

static std::vector<AdapterInfo> disabled_adapters;

inline void disconnect() {
    bilgi(t("network_disconnecting"));
    auto active = get_active_adapters();
    disabled_adapters.clear();

    for (auto& adapter : active) {
        // netsh interface set interface name="Name" admin=disabled
        std::wstring cmd = L"interface set interface name=\"" + adapter.wname + L"\" admin=disabled";
        
        // Use ShellExecute or CreateProcess to run netsh
        SHELLEXECUTEINFOW sei = { sizeof(sei) };
        sei.lpVerb = L"runas"; // Run as admin
        sei.lpFile = L"netsh.exe";
        sei.lpParameters = cmd.c_str();
        sei.nShow = SW_HIDE;
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;

        if (ShellExecuteExW(&sei)) {
            WaitForSingleObject(sei.hProcess, 5000);
            CloseHandle(sei.hProcess);
            disabled_adapters.push_back(adapter);
        }
    }
    
    if (!disabled_adapters.empty()) {
        basari(t("network_disconnected"));
    }
}

inline void reconnect() {
    if (disabled_adapters.empty()) return;

    bilgi(t("network_restoring"));
    for (auto& adapter : disabled_adapters) {
        std::wstring cmd = L"interface set interface name=\"" + adapter.wname + L"\" admin=enabled";
        
        SHELLEXECUTEINFOW sei = { sizeof(sei) };
        sei.lpVerb = L"runas"; 
        sei.lpFile = L"netsh.exe";
        sei.lpParameters = cmd.c_str();
        sei.nShow = SW_HIDE;
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;

        if (ShellExecuteExW(&sei)) {
            WaitForSingleObject(sei.hProcess, 5000);
            CloseHandle(sei.hProcess);
        }
    }
    disabled_adapters.clear();
    basari(t("network_restored"));
}

} // namespace Network
