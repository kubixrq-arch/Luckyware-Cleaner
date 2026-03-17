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
#include "ui.hpp"
#include "lang.hpp"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace Detector {

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

    PROCESSENTRY32W pe{};
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
    std::map<DWORD, std::string> malicious_pids;  // populated for --kill-process
};

inline MutexScanResult mutex_scan() {
    MutexScanResult result;
    section(t("mutex_title"));

    bilgi(t("mutex_static"));
    std::vector<std::pair<std::string, std::string>> static_mutexes = {
        {"Global\\PFLwrx",    "Luckyware Payload ana mutex (Pyld/dllmain.cpp:571)"},
        {"Global\\PFLwrxMNN", "Luckyware Payload ikincil mutex (Pyld/dllmain.cpp:586)"},
    };
    for (auto& [name, desc] : static_mutexes) {
        HANDLE h = OpenMutexA(SYNCHRONIZE, FALSE, name.c_str());
        if (h) {
            CloseHandle(h);
            tehdit(t("mutex_active", name));
            bilgi("  └─ " + desc);
            bilgi(t("mutex_lw_running"));
            result.found_mutexes.push_back(name);
        } else {
            basari(t("static_mutex", name));
        }
    }

    // Dynamic mutex pattern: Global\m<N> where N is zero-padded (TheDLL.cpp:117)
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
                bilgi("  └─ " + t("infdll_mutex"));
                result.found_mutexes.push_back(test_name);
            }
        }
    }

    bilgi(t("loader_checking"));
    std::vector<std::string> loader_prefixes = {"Global\\PFNMX_", "Global\\PFNX_"};
    for (auto& prefix : loader_prefixes) {
        for (auto& suffix : std::vector<std::string>{"test", "1234", "abcd", "ABCD", "0000"}) {
            std::string test_name = prefix + suffix;
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
    static const std::set<std::string> known_malicious = {
        "berok.exe", "zetolac.exe", "hpsr.exe"
    };

    for (auto& [pid, name] : procs) {
        if (known_malicious.count(name)) {
            tehdit(t("malicious_process", name));
            bilgi(t("dropper_running"));
            result.found_mutexes.push_back("process:" + name);
            result.malicious_pids[pid] = name;
        }
        if (std::regex_match(name, ox_re)) {
            tehdit(t("drop_process", name));
            result.found_mutexes.push_back("process:" + name);
            result.malicious_pids[pid] = name;
        }
        if (std::regex_match(name, bk_re)) {
            tehdit(t("sdk_drop_proc", name));
            result.found_mutexes.push_back("process:" + name);
            result.malicious_pids[pid] = name;
        }
        if (std::regex_match(name, hpsr_re)) {
            tehdit(t("imgui_drop_proc", name));
            result.found_mutexes.push_back("process:" + name);
            result.malicious_pids[pid] = name;
        }
    }

    std::cout << "\n";
    if (!result.found_mutexes.empty()) {
        std::cout << "  " << C::RED;
        for (int i = 0; i < 56; ++i) std::cout << "\u2588";
        std::cout << "\n  " << "  \u26a0  " << t("mutex_found_count", result.found_mutexes.size()) << "\n";
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

// Scans readable RW memory regions of known Luckyware target processes for the
// shared-memory signature 0xBA73593C (Loader.cpp:603).
// Limits scanning to 50 regions per process and 64 KB per region for performance.
inline LoaderResult loader_scan() {
    LoaderResult result;
    section(t("loader_title"));

    const DWORD SIGNATURE = 0xBA73593C;
    uint8_t sig_bytes[4];
    std::memcpy(sig_bytes, &SIGNATURE, 4);

    static const std::set<std::string> target_procs = {
        "dllhost.exe", "svchost.exe", "disksnapshot.exe",
        "fontdrvhost.exe", "icacls.exe", "ktmutil.exe",
        "label.exe", "legacynetuxhost.exe", "licensingdiag.exe"
    };

    auto procs = get_process_list();
    for (auto& [pid, name] : procs) {
        if (!target_procs.count(name)) continue;

        HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!hProc) continue;

        MEMORY_BASIC_INFORMATION mbi{};
        uintptr_t addr = 0;
        int regions_scanned = 0;
        bool found_sig = false;

        while (regions_scanned < 50) {
            if (!VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(mbi))) break;

            if (mbi.State == MEM_COMMIT &&
                (mbi.Protect & PAGE_READWRITE) &&
                mbi.RegionSize <= 0x100000) {
                size_t read_size = std::min(mbi.RegionSize, (SIZE_T)0x10000);
                std::vector<uint8_t> buf(read_size);
                SIZE_T bytes_read = 0;
                if (ReadProcessMemory(hProc, mbi.BaseAddress, buf.data(), read_size, &bytes_read)) {
                    auto it = std::search(buf.begin(), buf.begin() + bytes_read,
                                         sig_bytes, sig_bytes + 4);
                    if (it != buf.begin() + bytes_read) {
                        tehdit(t("loader_sharedmem", std::to_string(pid)));
                        bilgi("  \u2514\u2500 " + name + " (PID=" + std::to_string(pid) + ")");
                        bilgi("  \u2514\u2500 " + t("loader_running"));
                        ProcessInfo pi{pid, name, "shared_memory_signature"};
                        result.found.push_back(pi);
                        found_sig = true;
                        break;
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
        std::cout << "  " << C::RED << t("loader_found", result.found.size()) << C::RESET << "\n";
    }
    return result;
}

struct HollowResult {
    std::vector<ProcessInfo> found;
};

// Lightweight hollowing heuristic using CreateToolhelp32Snapshot + GetModuleFileNameEx.
// Flags anomalies: single thread count (CREATE_SUSPENDED indicator) or path mismatch
// between the expected system path and the actual executable path.
inline HollowResult hollow_scan() {
    HollowResult result;
    section(t("hollow_title"));

    struct TargetProc {
        std::string name;
        std::string expected_path;
        std::string expected_arg;  // reserved for future argument-based checks
    };

    std::vector<TargetProc> targets = {
        {"dllhost.exe",      "c:\\windows\\system32\\dllhost.exe",     "/processid:"},
        {"svchost.exe",      "c:\\windows\\system32\\svchost.exe",     "-k "},
        {"fontdrvhost.exe",  "c:\\windows\\system32\\fontdrvhost.exe", ""},
        {"disksnapshot.exe", "c:\\windows\\system32\\disksnapshot.exe",""},
        {"icacls.exe",       "c:\\windows\\system32\\icacls.exe",      ""},
        {"ktmutil.exe",      "c:\\windows\\system32\\ktmutil.exe",     ""},
    };

    for (auto& target : targets) {
        bilgi(t("check_proc") + C::CYAN + target.name);

        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap == INVALID_HANDLE_VALUE) continue;

        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                char nameBuf[MAX_PATH] = {};
                WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, nameBuf, MAX_PATH, nullptr, nullptr);
                std::string proc_name = nameBuf;
                std::transform(proc_name.begin(), proc_name.end(), proc_name.begin(), ::tolower);
                if (proc_name != target.name) continue;

                DWORD pid = pe.th32ProcessID;
                std::vector<std::string> anomalies;

                if (pe.cntThreads <= 1) {
                    anomalies.push_back(t("single_thread_proc"));
                }

                HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
                if (hProc) {
                    char path_buf[MAX_PATH] = {};
                    if (GetModuleFileNameExA(hProc, nullptr, path_buf, MAX_PATH)) {
                        std::string actual_path = path_buf;
                        std::transform(actual_path.begin(), actual_path.end(),
                                       actual_path.begin(), ::tolower);
                        if (!actual_path.empty() && actual_path != target.expected_path) {
                            anomalies.push_back(t("fake_path", actual_path));
                        }
                    } else {
                        anomalies.push_back(t("path_unreadable"));
                    }
                    CloseHandle(hProc);
                }

                if (!anomalies.empty()) {
                    tehdit(t("hollow_proc", target.name, std::to_string(pid)));
                    for (auto& a : anomalies)
                        bilgi("  \u2514\u2500 " + C::YELLOW + a + C::RESET);
                    ProcessInfo pi{pid, target.name, ""};
                    for (auto& a : anomalies) pi.reason += a + "; ";
                    result.found.push_back(pi);
                }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }

    std::cout << "\n";
    if (result.found.empty()) basari(t("hollow_clean"));
    else {
        std::cout << "  " << C::RED << "  \u26a0  " << t("hollow_found", result.found.size())
                  << C::RESET << "\n";
    }
    return result;
}

struct DnsResult {
    std::vector<ProcessInfo> found;
};

// Checks active TCP connections for established sessions from Luckyware target
// processes to dns.google IPs (8.8.8.8 / 8.8.4.4) on port 443 (DNS-over-HTTPS).
inline DnsResult dns_bypass_scan() {
    DnsResult result;
    section(t("dns_title"));
    bilgi(t("dns_checking"));

    static const std::set<DWORD> doh_ips_v4 = {
        0x08080808, // 8.8.8.8
        0x08080404, // 8.8.4.4
    };
    const WORD DOH_PORT = 443;

    auto proc_list = get_process_list();

    static const std::set<std::string> luckyware_procs = {
        "dllhost.exe", "svchost.exe", "fontdrvhost.exe",
        "disksnapshot.exe", "ktmutil.exe", "icacls.exe"
    };

    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (size == 0) {
        basari(t("dns_clean"));
        return result;
    }

    std::vector<BYTE> buffer(size);
    if (GetExtendedTcpTable(buffer.data(), &size, FALSE, AF_INET,
                             TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
        basari(t("dns_clean"));
        return result;
    }

    auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buffer.data());
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        auto& row = table->table[i];
        if (row.dwState != MIB_TCP_STATE_ESTAB) continue;
        WORD remote_port = ntohs((WORD)row.dwRemotePort);
        if (remote_port != DOH_PORT) continue;
        DWORD remote_ip = ntohl(row.dwRemoteAddr);
        if (!doh_ips_v4.count(remote_ip)) continue;

        DWORD pid = row.dwOwningPid;
        std::string proc_name = proc_list.count(pid) ? proc_list[pid] : "unknown";

        if (luckyware_procs.count(proc_name)) {
            tehdit(t("dns_found", std::to_string(pid), proc_name));
            bilgi("  \u2514\u2500 " + t("dns_bypass_active"));

            char ip_str[16];
            inet_ntop(AF_INET, &row.dwRemoteAddr, ip_str, sizeof(ip_str));
            bilgi("  \u2514\u2500 " + t("dns_target", std::string(ip_str)));

            ProcessInfo pi{pid, proc_name, "dns_doh_bypass"};
            result.found.push_back(pi);
        }
    }

    std::cout << "\n";
    if (result.found.empty()) basari(t("dns_clean"));
    else {
        tehdit(t("dns_found_count", result.found.size()));
    }
    return result;
}

struct RegistryResult {
    std::vector<std::string> found_keys;
};

inline RegistryResult registry_scan() {
    RegistryResult result;
    section(t("registry_title"));
    bilgi(t("registry_checking"));

    std::regex zararli_re(
        "(i-like\\.boats|krispykreme\\.top|nuzzyservices|devruntime\\.cy"
        "|luckyware\\.co|bounty-valorant\\.lol|vcc-redistrbutable"
        "|powershell.*windowstyle.*hidden"
        "|iwr\\s+-uri.*berok"
        "|berok\\.exe|zetolac\\.exe"
        "|VccFramework|PFLwrx|CDat\\.bin)",
        std::regex::icase
    );

    struct HiveInfo {
        HKEY hive;
        std::string path;
    };
    std::vector<HiveInfo> hive_paths = {
        {HKEY_CURRENT_USER,  "Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
        {HKEY_CURRENT_USER,  "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"},
        {HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"},
        {HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"},
        {HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"},
    };

    for (auto& hi : hive_paths) {
        HKEY hkey = nullptr;
        if (RegOpenKeyExA(hi.hive, hi.path.c_str(), 0,
                          KEY_READ, &hkey) != ERROR_SUCCESS) continue;

        DWORD index = 0;
        char name[256] = {};
        BYTE data[2048] = {};
        while (true) {
            DWORD name_len = sizeof(name);
            DWORD data_len = sizeof(data);
            DWORD type;
            if (RegEnumValueA(hkey, index++, name, &name_len, nullptr,
                              &type, data, &data_len) != ERROR_SUCCESS) break;

            std::string val(reinterpret_cast<char*>(data), data_len);
            if (std::regex_search(val, zararli_re)) {
                std::string key_path = hi.path + "\\" + name;
                uyari(t("registry_found", key_path,
                         val.size() > 80 ? val.substr(0, 80) + "..." : val));
                result.found_keys.push_back(key_path);
            }
            std::memset(name, 0, sizeof(name));
            std::memset(data, 0, sizeof(data));
        }
        RegCloseKey(hkey);
    }

    if (result.found_keys.empty()) basari(t("registry_clean"));
    return result;
}

inline int kill_processes(const std::map<DWORD, std::string>& pids) {
    section(t("kill_title"));
    if (pids.empty()) {
        bilgi(t("kill_none"));
        return 0;
    }
    int killed = 0;
    for (auto& [pid, name] : pids) {
        HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (h) {
            if (TerminateProcess(h, 1)) {
                basari(t("kill_success", std::to_string(pid), name));
                ++killed;
            } else {
                uyari(t("kill_fail", std::to_string(pid)));
            }
            CloseHandle(h);
        } else {
            uyari(t("kill_fail", std::to_string(pid)));
        }
    }
    if (killed > 0)
        bilgi(t("kill_count", std::to_string(killed)));
    return killed;
}

struct C2Result {
    std::vector<std::string> found_domains;
};

// Resolves each domain via getaddrinfo. If it resolves to anything other than
// 0.0.0.0 the domain is not blocked in HOSTS and is added to found_domains.
inline C2Result github_c2_check(const std::vector<std::string>& domains) {
    C2Result result;
    bilgi(t("c2_github_check"));

    for (auto& domain : domains) {
        if (domain.empty()) continue;
        struct addrinfo* res = nullptr;
        struct addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(domain.c_str(), "80", &hints, &res) == 0) {
            char ip[INET6_ADDRSTRLEN];
            if (res->ai_family == AF_INET) {
                inet_ntop(AF_INET,
                    &((struct sockaddr_in*)res->ai_addr)->sin_addr, ip, sizeof(ip));
            } else {
                inet_ntop(AF_INET6,
                    &((struct sockaddr_in6*)res->ai_addr)->sin6_addr, ip, sizeof(ip));
            }
            std::string ip_str = ip;
            if (ip_str != "0.0.0.0") {
                uyari(t("c2_not_blocked", domain, ip_str));
                result.found_domains.push_back(domain);
            }
            freeaddrinfo(res);
        }
    }
    return result;
}

inline int block_domains(const std::vector<std::string>& domains) {
    section(t("hosts_title"));
    const std::string hosts_path = "C:\\Windows\\System32\\drivers\\etc\\hosts";

    std::ifstream rf(hosts_path);
    if (!rf.is_open()) {
        hata(t("hosts_read_err"));
        return 0;
    }
    std::string content((std::istreambuf_iterator<char>(rf)),
                         std::istreambuf_iterator<char>());
    rf.close();

    int blocked = 0;
    std::ofstream wf(hosts_path, std::ios::app);
    if (!wf.is_open()) {
        hata(t("hosts_write_err"));
        return 0;
    }

    for (auto& domain : domains) {
        if (domain.empty()) continue;
        if (content.find(domain) == std::string::npos) {
            wf << "\n0.0.0.0 " << domain;
            basari(t("hosts_blocked", domain));
            ++blocked;
        }
    }
    wf.close();
    if (blocked > 0)
        bilgi(t("hosts_block_done", std::to_string(blocked)));
    return blocked;
}

} // namespace Detector
