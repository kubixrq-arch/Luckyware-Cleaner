#pragma once
// Luckyware Cleaner - Detector Module
// Runtime detection: Mutex, Process, Loader (shared-memory signature),
// Process Hollowing (WMIC), DNS-over-HTTPS bypass, Registry scan, C2 domain check.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wbemidl.h>
#include <comutil.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <regex>
#include <algorithm>
#include <sstream>
#include <fstream>
#include <filesystem>
#include "ui.hpp"
#include "lang.hpp"
#include "obfuscate.hpp"
#include "pe_check.hpp"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace Detector {

namespace fs = std::filesystem;
using namespace UI;
using namespace Lang;

struct ProcessInfo {
    DWORD pid;
    std::string name;
    std::string reason;
};

inline std::map<DWORD, std::string> get_process_list() {
    std::map<DWORD, std::string> procs;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return procs;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            char nameBuf[MAX_PATH] = {};
            WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, nameBuf, MAX_PATH, nullptr, nullptr);
            std::string name = nameBuf;
            std::transform(name.begin(), name.end(), name.begin(), ::tolower);
            procs[pe.th32ProcessID] = name;
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return procs;
}

struct MutexScanResult {
    std::vector<std::string> found_mutexes;
    std::map<DWORD, std::string> malicious_pids;
};

inline MutexScanResult mutex_scan() {
    MutexScanResult result;
    section(t("mutex_title"));

    bilgi(t("mutex_static"));
    std::vector<std::pair<std::string, std::string>> static_mutexes;
    static_mutexes.push_back({"Global\\PFLwrx",    "Luckyware Payload ana mutex"});
    static_mutexes.push_back({"Global\\PFLwrxMNN", "Luckyware Payload ikincil mutex"});
    static_mutexes.push_back({"Global\\ox_loader", "Luckyware Dropper/Loader mutex"});
    
    for (size_t i = 0; i < static_mutexes.size(); ++i) {
        std::string name = static_mutexes[i].first;
        std::string desc = static_mutexes[i].second;
        HANDLE h = OpenMutexA(SYNCHRONIZE, FALSE, name.c_str());
        if (h) {
            CloseHandle(h);
            tehdit(t("mutex_active", name));
            bilgi("  \u2514\u2500 " + desc);
            bilgi(t("mutex_lw_running"));
            result.found_mutexes.push_back(name);
        } else {
            basari(t("static_mutex", name));
        }
    }

    bilgi(t("mutex_dynamic"));
    for (int len = 4; len <= 8; ++len) {
        for (int i = 0; i < 10000; i += 1000) {
            std::ostringstream oss;
            oss << "Global\\m" << std::setw(len) << std::setfill('0') << i;
            std::string test_name = oss.str();
            HANDLE h = OpenMutexA(SYNCHRONIZE, FALSE, test_name.c_str());
            if (h) {
                CloseHandle(h);
                tehdit(t("dynamic_mutex_found", test_name));
                bilgi("  \u2514\u2500 " + t("infdll_mutex"));
                result.found_mutexes.push_back(test_name);
            }
        }
    }

    bilgi(t("loader_checking"));
    std::vector<std::string> loader_prefixes;
    loader_prefixes.push_back("Global\\PFNMX_");
    loader_prefixes.push_back("Global\\PFNX_");
    for (size_t p = 0; p < loader_prefixes.size(); ++p) {
        std::string prefix = loader_prefixes[p];
        std::vector<std::string> suffixes;
        suffixes.push_back("test"); suffixes.push_back("1234"); suffixes.push_back("abcd");
        for (size_t s = 0; s < suffixes.size(); ++s) {
            std::string test_name = prefix + suffixes[s];
            HANDLE h = OpenMutexA(SYNCHRONIZE, FALSE, test_name.c_str());
            if (h) {
                CloseHandle(h);
                tehdit(t("loader_pfnmx", test_name));
                bilgi(t("loader_running"));
                result.found_mutexes.push_back(test_name);
            }
        }
    }

    bilgi(t("mutex_processes"));
    auto procs = get_process_list();
    std::regex ox_re("^ox_\\d+\\.exe$");
    std::regex bk_re("^bk\\d{6}\\.exe$");
    std::regex hpsr_re("^hpsr\\d{6}\\.exe$");
    std::vector<std::string> known_malicious = Obf::known_malicious_names();
    std::set<std::string> known_malicious_set(known_malicious.begin(), known_malicious.end());

    for (std::map<DWORD, std::string>::iterator it = procs.begin(); it != procs.end(); ++it) {
        DWORD pid = it->first;
        std::string name = it->second;
        if (known_malicious_set.count(name)) {
            tehdit(t("malicious_process", name));
            bilgi(t("dropper_running"));
            result.found_mutexes.push_back("process:" + name);
            result.malicious_pids[pid] = name;
        }
        if (std::regex_match(name, ox_re) || std::regex_match(name, bk_re) || std::regex_match(name, hpsr_re)) {
            tehdit(t("drop_process", name));
            result.found_mutexes.push_back("process:" + name);
            result.malicious_pids[pid] = name;
        }
    }

    std::cout << "\n";
    if (!result.found_mutexes.empty()) {
        std::cout << "  " << C::RED;
        for (int i = 0; i < 56; ++i) std::cout << "\u2588";
        std::cout << "\n  " << "  \u26a0  " << t("mutex_found_count", std::to_string(result.found_mutexes.size())) << "\n";
        for (int i = 0; i < 56; ++i) std::cout << "\u2588";
        std::cout << C::RESET << "\n";
    } else {
        basari(t("mutex_clean"));
    }
    return result;
}

struct LoaderResult {
    std::vector<ProcessInfo> found;
};

inline LoaderResult loader_scan() {
    LoaderResult result;
    section(t("loader_title"));

    const DWORD SIGNATURE = 0xBA73593C;
    uint8_t sig_bytes[4];
    std::memcpy(sig_bytes, &SIGNATURE, 4);

    static const char* target_arr[] = {
        "dllhost.exe", "svchost.exe", "disksnapshot.exe",
        "fontdrvhost.exe", "icacls.exe", "ktmutil.exe",
        "label.exe", "legacynetuxhost.exe", "licensingdiag.exe"
    };
    std::set<std::string> target_procs;
    for (int i = 0; i < 9; ++i) target_procs.insert(target_arr[i]);

    auto procs = get_process_list();
    for (std::map<DWORD, std::string>::iterator it = procs.begin(); it != procs.end(); ++it) {
        DWORD pid = it->first;
        std::string name = it->second;
        if (!target_procs.count(name)) continue;

        HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!hProc) continue;

        MEMORY_BASIC_INFORMATION mbi;
        uintptr_t addr = 0;
        int regions_scanned = 0;
        bool found_sig = false;

        while (regions_scanned < 50) {
            if (!VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(mbi))) break;
            if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_READWRITE) && mbi.RegionSize <= 0x100000) {
                size_t read_size = std::min((SIZE_T)mbi.RegionSize, (SIZE_T)0x10000);
                std::vector<uint8_t> buf(read_size);
                SIZE_T bytes_read = 0;
                if (ReadProcessMemory(hProc, mbi.BaseAddress, buf.data(), read_size, &bytes_read)) {
                    auto search_it = std::search(buf.begin(), buf.begin() + bytes_read, sig_bytes, sig_bytes + 4);
                    if (search_it != buf.begin() + bytes_read) {
                        tehdit(t("loader_sharedmem", std::to_string(pid)));
                        bilgi("  \u2514\u2500 " + name + " (PID=" + std::to_string(pid) + ")");
                        bilgi("  \u2514\u2500 " + t("loader_running"));
                        ProcessInfo pi = {pid, name, "shared_memory_signature"};
                        result.found.push_back(pi);
                        found_sig = true; break;
                    }
                }
                regions_scanned++;
            }
            addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
            if (addr > 0x7FFFFFFFFFFF) break;
        }
        CloseHandle(hProc);
        if (found_sig) break;
    }

    std::cout << "\n";
    if (result.found.empty()) basari(t("loader_clean"));
    else {
        std::cout << "  " << C::RED << t("loader_found", std::to_string(result.found.size())) << C::RESET << "\n";
    }
    return result;
}

struct HollowResult {
    std::vector<ProcessInfo> found;
};

inline HollowResult hollow_scan() {
    HollowResult result;
    section(t("hollow_title"));

    struct TargetProc { std::string name; std::string expected_path; };
    std::vector<TargetProc> targets;
    targets.push_back({"dllhost.exe",      "c:\\windows\\system32\\dllhost.exe"});
    targets.push_back({"svchost.exe",      "c:\\windows\\system32\\svchost.exe"});
    targets.push_back({"fontdrvhost.exe",  "c:\\windows\\system32\\fontdrvhost.exe"});
    targets.push_back({"disksnapshot.exe", "c:\\windows\\system32\\disksnapshot.exe"});
    targets.push_back({"icacls.exe",       "c:\\windows\\system32\\icacls.exe"});
    targets.push_back({"ktmutil.exe",      "c:\\windows\\system32\\ktmutil.exe"});
    targets.push_back({"label.exe",        "c:\\windows\\system32\\label.exe"});
    targets.push_back({"logman.exe",       "c:\\windows\\system32\\logman.exe"});
    targets.push_back({"pathping.exe",     "c:\\windows\\system32\\pathping.exe"});
    targets.push_back({"print.exe",        "c:\\windows\\system32\\print.exe"});
    targets.push_back({"reg.exe",          "c:\\windows\\system32\\reg.exe"});
    targets.push_back({"sc.exe",           "c:\\windows\\system32\\sc.exe"});
    targets.push_back({"sihost.exe",       "c:\\windows\\system32\\sihost.exe"});

    for (size_t i = 0; i < targets.size(); ++i) {
        std::string target_name = targets[i].name;
        std::string expected_path = targets[i].expected_path;
        bilgi(t("check_proc") + C::CYAN + target_name);

        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap == INVALID_HANDLE_VALUE) continue;

        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                char nameBuf[MAX_PATH] = {};
                WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, nameBuf, MAX_PATH, nullptr, nullptr);
                std::string proc_name = nameBuf;
                std::transform(proc_name.begin(), proc_name.end(), proc_name.begin(), ::tolower);
                if (proc_name != target_name) continue;

                DWORD pid = pe.th32ProcessID;
                std::vector<std::string> anomalies;

                if (pe.cntThreads <= 1 && target_name != "svchost.exe") {
                    anomalies.push_back(t("single_thread_proc"));
                }

                bool path_mismatch = false;
                HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
                if (hProc) {
                    char path_buf[MAX_PATH] = {};
                    if (GetModuleFileNameExA(hProc, nullptr, path_buf, MAX_PATH)) {
                        std::string actual_path = path_buf;
                        std::transform(actual_path.begin(), actual_path.end(), actual_path.begin(), ::tolower);
                        if (!actual_path.empty() && actual_path != expected_path) {
                            anomalies.push_back(t("fake_path", actual_path));
                            path_mismatch = true;
                        }
                    } else if (target_name != "svchost.exe") {
                        anomalies.push_back(t("path_unreadable"));
                    }
                    CloseHandle(hProc);
                }

                bool should_flag = !anomalies.empty();
                if (target_name == "svchost.exe" && !path_mismatch) should_flag = false;

                if (should_flag) {
                    tehdit(t("hollow_proc", target_name, std::to_string(pid)));
                    std::string reason = "";
                    for (size_t a = 0; a < anomalies.size(); ++a) {
                        bilgi("  \u2514\u2500 " + C::YELLOW + anomalies[a] + C::RESET);
                        reason += anomalies[a] + "; ";
                    }
                    ProcessInfo pi = {pid, target_name, reason};
                    result.found.push_back(pi);
                }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }

    std::cout << "\n";
    if (result.found.empty()) basari(t("hollow_clean"));
    else {
        std::cout << "  " << C::RED << "  \u26a0  " << t("hollow_found", std::to_string(result.found.size())) << C::RESET << "\n";
    }
    return result;
}

struct DnsResult { std::vector<ProcessInfo> found; };
inline DnsResult dns_bypass_scan() {
    DnsResult result;
    section(t("dns_title"));
    bilgi(t("dns_checking"));

    static const DWORD doh_ips[] = { 0x08080808, 0x08080404 };
    const WORD DOH_PORT = 443;
    auto proc_list = get_process_list();
    static const char* lucky_arr[] = { "dllhost.exe", "svchost.exe", "fontdrvhost.exe", "disksnapshot.exe", "ktmutil.exe", "icacls.exe" };
    std::set<std::string> lucky_procs;
    for (int i = 0; i < 6; ++i) lucky_procs.insert(lucky_arr[i]);

    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (size > 0) {
        std::vector<BYTE> buffer(size);
        if (GetExtendedTcpTable(buffer.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buffer.data());
            for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                auto& row = table->table[i];
                if (row.dwState != MIB_TCP_STATE_ESTAB) continue;
                if (ntohs((WORD)row.dwRemotePort) != DOH_PORT) continue;
                DWORD r_ip = ntohl(row.dwRemoteAddr);
                if (r_ip == doh_ips[0] || r_ip == doh_ips[1]) {
                    DWORD pid = row.dwOwningPid;
                    std::string p_name = proc_list.count(pid) ? proc_list[pid] : "unknown";
                    if (lucky_procs.count(p_name)) {
                        tehdit(t("dns_found", std::to_string(pid), p_name));
                        char ip_s[16]; inet_ntop(AF_INET, &row.dwRemoteAddr, ip_s, 16);
                        bilgi("  \u2514\u2500 " + t("dns_target", std::string(ip_s)));
                        ProcessInfo pi = {pid, p_name, "dns_doh_bypass"};
                        result.found.push_back(pi);
                    }
                }
            }
        }
    }
    std::cout << "\n";
    if (result.found.empty()) basari(t("dns_clean"));
    else tehdit(t("dns_found_count", std::to_string(result.found.size())));
    return result;
}

struct RegistryResult { std::vector<std::string> found_keys; };
inline RegistryResult registry_scan() {
    RegistryResult result;
    section(t("registry_title"));
    bilgi(t("registry_checking"));
    std::regex re(Obf::registry_regex_pattern(), std::regex::icase);
    struct HiveInfo { HKEY hive; const char* path; };
    HiveInfo hives[4] = {
        {HKEY_CURRENT_USER,  "Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
        {HKEY_CURRENT_USER,  "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"},
        {HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"},
        {HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"}
    };
    for (int i = 0; i < 4; ++i) {
        HKEY hKey = nullptr;
        if (RegOpenKeyExA(hives[i].hive, hives[i].path, 0, KEY_READ, &hKey) != ERROR_SUCCESS) continue;
        DWORD idx = 0;
        char name[256]; BYTE data[2048];
        while (true) {
            DWORD nLen = 256, dLen = 2048, type;
            if (RegEnumValueA(hKey, idx++, name, &nLen, nullptr, &type, data, &dLen) != ERROR_SUCCESS) break;
            std::string val(reinterpret_cast<char*>(data), dLen);
            if (std::regex_search(val, re)) {
                std::string k_path = std::string(hives[i].path) + "\\" + name;
                uyari(t("registry_found", k_path, val.size() > 80 ? val.substr(0, 80) : val));
                result.found_keys.push_back(k_path);
            }
        }
        RegCloseKey(hKey);
    }
    if (result.found_keys.empty()) basari(t("registry_clean"));
    return result;
}

inline bool enable_debug_privilege_det() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return false;
    LUID luid; LookupPrivilegeValueA(nullptr, "SeDebugPrivilege", &luid);
    TOKEN_PRIVILEGES tp; tp.PrivilegeCount = 1; tp.Privileges[0].Luid = luid; tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    CloseHandle(hToken); return true;
}

inline int kill_processes(const std::map<DWORD, std::string>& pids) {
    if (pids.empty()) return 0;
    section(t("kill_title")); enable_debug_privilege_det();
    int killed = 0;
    for (std::map<DWORD, std::string>::const_iterator it = pids.begin(); it != pids.end(); ++it) {
        HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, it->first);
        if (h) { if (TerminateProcess(h, 1)) { basari(t("kill_success", std::to_string(it->first), it->second)); ++killed; } CloseHandle(h); }
    }
    return killed;
}

struct C2Result { std::vector<std::string> found_domains; };
inline C2Result github_c2_check(const std::vector<std::string>& domains) {
    C2Result result;
    for (size_t i = 0; i < domains.size(); ++i) {
        struct addrinfo *res = nullptr, hints{}; hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(domains[i].c_str(), "80", &hints, &res) == 0) { result.found_domains.push_back(domains[i]); freeaddrinfo(res); }
    }
    return result;
}

inline int block_domains(const std::vector<std::string>& domains) {
    section(t("hosts_title")); int count = 0;
    std::ofstream wf("C:\\Windows\\System32\\drivers\\etc\\hosts", std::ios::app);
    for (size_t i = 0; i < domains.size(); ++i) { wf << "\n0.0.0.0 " << domains[i]; basari(t("hosts_blocked", domains[i])); ++count; }
    return count;
}

inline void check_system_integrity() {
    section(t("sys_integrity_title"));
    fs::path cp = "C:\\Windows\\System32\\cldapi.dll";
    if (fs::exists(cp)) {
        bilgi(t("checking_cldapi"));
        PECheck::RcdResult r = PECheck::check_rcd_sections(cp.string());
        if (r.found) { tehdit(t("cldapi_infected")); bilgi("  \u2514\u2500 " + r.reason); }
        else basari(t("cldapi_clean"));
    }
}

} // namespace Detector
