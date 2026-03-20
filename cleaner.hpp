#pragma once
// Luckyware Cleaner - Cleaner Module
// Handles: VCXPROJ, SUO, SDK, ImGui, HOSTS, Registry, Discord, Edge, VS EXEs, Antigravity IDE
#include <string>
#include <vector>
#include <set>
#include <map>
#include <regex>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <filesystem>
#include <windows.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include "ui.hpp"
#include "lang.hpp"
#include "obfuscate.hpp"

namespace Cleaner {

namespace fs = std::filesystem;
using namespace UI;
using namespace Lang;

// Parses .vcxproj files and removes any <PreBuildEvent> tags containing injected MSBuild logic.
// Uses regex (icase) to handle tag casing variations across different VS versions.
inline bool clean_vcxproj(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return false;
    std::string content((std::istreambuf_iterator<char>(f)),
                         std::istreambuf_iterator<char>());
    f.close();

    // Scan all possible build event tags: PreBuildEvent, PostBuildEvent, CustomBuildStep
    std::vector<std::regex> event_blocks = {
        std::regex(R"(\s*<PreBuildEvent>[\s\S]*?<\/PreBuildEvent>\s*)",  std::regex::icase),
        std::regex(R"(\s*<PostBuildEvent>[\s\S]*?<\/PostBuildEvent>\s*)", std::regex::icase),
        std::regex(R"(\s*<CustomBuildStep>[\s\S]*?<\/CustomBuildStep>\s*)", std::regex::icase)
    };

    bool changed = false;
    std::string new_content = content;

    for (auto& re : event_blocks) {
        if (std::regex_search(new_content, re)) {
            new_content = std::regex_replace(new_content, re, "\n");
            changed = true;
        }
    }

    if (changed) {
        std::ofstream wf(path);
        wf << new_content;
        basari(t("vcxproj_cleaned", path));
    }
    return changed;
}

inline bool clean_suo(const std::string& path) {
    try {
        fs::remove(path);
        basari(t("suo_deleted", path));
        return true;
    } catch (std::exception& e) {
        hata(t("suo_del_err", e.what()));
        return false;
    }
}

// Scans Windows Kits directories (windows.h, winnetwk.h) to purge injected VccLibaries sub-namespaces.
// Also patches winnetwk.h EOF truncation issues caused by the infection.
inline std::vector<std::string> clean_sdk() {
    section(t("sdk_title"));
    bilgi(t("sdk_cleaning"));

    std::vector<std::string> cleaned;
    
    // Pattern for VccLibaries namespace or VCCLibraries_wfkuuv marker
    std::regex vcc_block(
        R"((namespace\s+VccLibaries\s*\{[\s\S]*?\}\s*//\s*namespace\s+VccLibaries[^\n]*\n?)|(#ifdef\s+__cplusplus[\s\S]*?VCCLibraries_wfkuuv157wg2gjthwla0lwbo1493h7[\s\S]*?#endif[\s\S]*?#endif\s+//\s*_WINNETWK_))",
        std::regex::icase
    );
    
    std::vector<std::string> sdk_roots = {
        "C:\\Program Files (x86)\\Windows Kits\\10\\Include",
        "C:\\Program Files\\Windows Kits\\10\\Include",
    };

    std::set<std::string> target_files = {"windows.h", "winnetwk.h"};

    for (auto& root : sdk_roots) {
        if (!fs::exists(root)) continue;
        try {
            for (auto& entry : fs::recursive_directory_iterator(root,
                    fs::directory_options::skip_permission_denied)) {
                if (!entry.is_regular_file()) continue;
                std::string fname = entry.path().filename().string();
                if (target_files.find(fname) == target_files.end()) continue;

                std::string fpath = entry.path().string();
                std::ifstream rf(fpath);
                if (!rf.is_open()) continue;
                std::string content((std::istreambuf_iterator<char>(rf)),
                                     std::istreambuf_iterator<char>());
                rf.close();

                // Check for infection markers
                if (content.find(Obf::marker_vcclib()) == std::string::npos && 
                    content.find(Obf::marker_vcclib2()) == std::string::npos &&
                    content.find(Obf::marker_wfkuuv()) == std::string::npos) continue;

                uyari(t("sdk_infection_found", fpath));

                // Special handling for winnetwk.h to restore the correct epilogue
                if (fname == "winnetwk.h") {
                    size_t pos = content.find("#ifdef __cplusplus");
                    // Backtrack from a known malware marker to the last legitimate block
                    size_t marker_pos = content.find(Obf::marker_vcclib2());
                    if (marker_pos != std::string::npos) {
                        // Keep only standard winnetwk.h usually about 900+ lines
                        // For a quick fix, we'll restore a known good epilogue if we detect the broken one.
                        std::string restored = content;
                        size_t cut = marker_pos;
                        // Backtrack to the previous #endif
                         while (true) {
                            size_t last_endif = restored.rfind("#endif", cut - 1);
                            if (last_endif == std::string::npos || last_endif < marker_pos - 1000) break; 
                            cut = last_endif;
                            // Winnetwk usually ends after Desktop/System Family partition region ends.
                            if (restored.substr(last_endif, 200).find("WINAPI_PARTITION_SYSTEM") != std::string::npos) break;
                        }
                        
                        restored = restored.substr(0, cut);
                        restored += "#endif /* WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP | WINAPI_PARTITION_SYSTEM) */\n#pragma endregion\n\n#if _MSC_VER >= 1200\n#pragma warning(pop)\n#endif\n\n#ifdef __cplusplus\n}\n#endif\n\n#endif // _WINNETWK_\n";
                        
                        if (restored != content) {
                            std::ofstream wf(fpath);
                            wf << restored;
                            basari(t("sdk_file_fixed", fpath));
                            cleaned.push_back(fpath);
                            continue;
                        }
                    }
                }

                std::string cleaned_content = std::regex_replace(content, vcc_block, "");
                if (cleaned_content != content) {
                    std::ofstream wf(fpath);
                    wf << cleaned_content;
                    basari(t("sdk_cleaned", fpath));
                    cleaned.push_back(fpath);
                }
            }
        } catch (...) {}
    }

    if (cleaned.empty()) basari(t("sdk_clean"));
    return cleaned;
}

// Flushes %TEMP% and %TMP% directories to remove staged payloads.
// Locked files are skipped to avoid permission faults.
inline void empty_temp_folders() {
    section(t("temp_clean_title"));
    bilgi(t("temp_cleaning"));

    std::vector<std::string> temp_vars = {"TEMP", "TMP"};
    int deleted_count = 0;
    int skipped_count = 0;

    for (const auto& var : temp_vars) {
        char* buf = nullptr;
        size_t len = 0;
        if (_dupenv_s(&buf, &len, var.c_str()) == 0 && buf != nullptr) {
            std::string temp_path(buf);
            free(buf);

            if (!fs::exists(temp_path)) continue;

            // Her alt öğeyi ayrı ayrı sil (kilitli olanları atla)
            try {
                for (auto& entry : fs::directory_iterator(
                        temp_path, fs::directory_options::skip_permission_denied)) {
                    try {
                        std::uintmax_t n = fs::remove_all(entry.path());
                        if (n > 0) deleted_count += (int)n;
                    } catch (...) {
                        ++skipped_count;
                    }
                }
            } catch (...) {}
        }
    }

    if (deleted_count > 0) {
        basari(t("temp_files_deleted", std::to_string(deleted_count)));
    } else {
        basari(t("temp_already_clean"));
    }
    if (skipped_count > 0) {
        uyari(t("temp_files_skipped", std::to_string(skipped_count)));
    }
}


// Sanitizes imgui_impl_win32.cpp across common user directories by stripping:
// 1. Hex-encoded string payloads (std::string F... = "\x...")
// 2. System execution calls (system(F...c_str()))
// 3. Extraneous comments left by the infection
inline std::vector<std::string> clean_imgui(const std::string& search_root = "C:\\Users") {
    section(t("imgui_title"));

    // 1. Broad regex for any variable assigned a long hex string (usually Luckyware payload)
    // 2. Multiline hex string support: \x[0-9a-f]{2} repeated many times
    // 3. Corresponding system() call using that variable
    std::vector<std::regex> patterns = {
        // Matches: std::string VarName = "\xAB\xCD..."; (even if split across lines)
        std::regex(R"(^\s*std::string\s+[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*"(?:\\x[0-9a-fA-F]{2}[\s\n]*)+";\s*$)"),
        // Matches: system(VarName.c_str());
        std::regex(R"(^\s*system\([a-zA-Z_][a-zA-Z0-9_]*\.c_str\(\)\)\s*;\s*$)"),
        // Specific marker cleanup
        std::regex(R"(\s*//\s*Luckyware[^\n]*\n?)"),
        std::regex(R"(\s*//\s*VccLibaries[^\n]*\n?)"),
    };

    std::vector<std::string> cleaned;
    std::vector<std::string> search_roots = {
        "C:\\Users",
        "C:\\Program Files",
        "C:\\Program Files (x86)",
    };

    for (auto& root : search_roots) {
        if (!fs::exists(root)) continue;
        try {
            for (auto& entry : fs::recursive_directory_iterator(root,
                    fs::directory_options::skip_permission_denied)) {
                if (!entry.is_regular_file()) continue;
                auto fname = entry.path().filename().string();
                if (fname != "imgui_impl_win32.cpp") continue;

                std::string fpath = entry.path().string();
                // Skip Windows system directories to avoid false positives
                std::string lower_path = fpath;
                std::transform(lower_path.begin(), lower_path.end(), lower_path.begin(), ::tolower);
                if (lower_path.find("windows\\system") != std::string::npos) continue;

                std::ifstream rf(fpath);
                if (!rf.is_open()) continue;
                std::string content((std::istreambuf_iterator<char>(rf)),
                                     std::istreambuf_iterator<char>());
                rf.close();

                if (content.find(Obf::marker_vcclib()) == std::string::npos &&
                    content.find(Obf::marker_systemf()) == std::string::npos) continue;

                std::string cleaned_content = content;
                for (auto& re : patterns) {
                    cleaned_content = std::regex_replace(cleaned_content, re, "");
                }

                if (cleaned_content != content) {
                    std::ofstream wf(fpath);
                    wf << cleaned_content;
                    basari(t("imgui_cleaned", fpath));
                    cleaned.push_back(fpath);
                }
            }
        } catch (...) {}
    }

    if (cleaned.empty()) basari(t("imgui_clean"));
    return cleaned;
}

// Injects known Luckyware C2 domains into the local HOSTS file pointing to 0.0.0.0
// to null-route future callbacks.
inline int update_hosts(std::vector<std::string> domains = {
    "pubshierstext.top", "frozi.cc", "concodro.lat", "krispykreme.top",
    "wallmart.mom", "stratum.ravenminer.com", "matchashop.icu",
    "vcc-library.online", "vcc-library.help", "i-slept-with-ur.mom",
    "i-like.boats", "devruntime.cy", "zetolacs-cloud.top", "exo-api.tf",
    "nuzzyservices.com", "darkside.cy", "balista.lol", "phobos.top",
    "phobosransom.com", "pee-files.nl", "vcc-library.uk", "luckyware.co",
    "luckyware.cc", "91.92.243.218", "dhszo.darkside.cy", "188.114.96.11",
    "risesmp.net", "luckystrike.pw", "vcc-redistrbutable.help"
}) {
    if (domains.empty()) return 0;
    section(t("hosts_title"));
    bilgi(t("hosts_blocking_c2"));

    const std::string hosts_path = "C:\\Windows\\System32\\drivers\\etc\\hosts";
    std::ifstream rf(hosts_path);
    std::string content = "";
    if (rf.is_open()) {
        content.assign((std::istreambuf_iterator<char>(rf)), std::istreambuf_iterator<char>());
        rf.close();
    }

    int added = 0;
    std::ofstream wf(hosts_path, std::ios::app);
    for (auto& dom : domains) {
        if (content.find(dom) == std::string::npos) {
            wf << "\n0.0.0.0 " << dom;
            uyari(t("hosts_added_c2", dom));
            added++;
        }
    }
    wf.close();

    if (added > 0) basari(t("hosts_blocked_new", std::to_string(added)));
    else basari(t("hosts_all_safe"));

    return added;
}

// Enumerates HKCU/HKLM Run and RunOnce keys for persistence mechanisms.
// Uses a two-pass approach (collect -> delete) to prevent index shifting during iteration.
inline int clean_registry() {
    section(t("registry_title"));
    bilgi(t("registry_checking"));

    std::regex zararli_re(Obf::registry_regex_pattern(), std::regex::icase);

    struct HiveInfo { HKEY hive; std::string path; };
    std::vector<HiveInfo> hives = {
        {HKEY_CURRENT_USER,  "Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
        {HKEY_CURRENT_USER,  "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"},
        {HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"},
        {HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"},
    };

    int deleted = 0;
    for (auto& hi : hives) {
        HKEY hkey;
        if (RegOpenKeyExA(hi.hive, hi.path.c_str(), 0,
                          KEY_READ | KEY_SET_VALUE, &hkey) != ERROR_SUCCESS) continue;

        std::vector<std::string> to_delete;
        DWORD index = 0;
        char name[256] = {};
        BYTE data[2048] = {};
        while (true) {
            DWORD name_len = sizeof(name), data_len = sizeof(data), type;
            if (RegEnumValueA(hkey, index++, name, &name_len, nullptr,
                              &type, data, &data_len) != ERROR_SUCCESS) break;
            std::string val(reinterpret_cast<char*>(data), data_len);
            if (std::regex_search(val, zararli_re)) {
                uyari(t("registry_found", std::string(name), val.substr(0, 80)));
                to_delete.push_back(name);
            }
            std::memset(name, 0, sizeof(name));
            std::memset(data, 0, sizeof(data));
        }

        for (auto& key_name : to_delete) {
            if (RegDeleteValueA(hkey, key_name.c_str()) == ERROR_SUCCESS) {
                basari(t("registry_deleted", key_name));
                ++deleted;
            }
        }
        RegCloseKey(hkey);
    }

    if (deleted == 0) basari(t("registry_clean"));
    return deleted;
}

// Invokes the winget CLI to resolve a target application's Publisher.AppName ID.
// Falls back to the raw query string if extraction fails.
inline std::string find_winget_id(const std::string& program_name) {
    std::string cmd = "winget list --name \"" + program_name + "\" --disable-interactivity 2>nul";
    FILE* pipe = _popen(cmd.c_str(), "r");
    if (!pipe) return program_name;

    char buf[512];
    std::string output;
    while (fgets(buf, sizeof(buf), pipe)) output += buf;
    _pclose(pipe);

    std::regex id_re(R"(\b([A-Za-z][A-Za-z0-9]+\.[A-Za-z][A-Za-z0-9]+)\b)");
    std::smatch m;
    std::istringstream iss(output);
    std::string line;
    while (std::getline(iss, line)) {
        std::string lower_line = line;
        std::transform(lower_line.begin(), lower_line.end(), lower_line.begin(), ::tolower);
        std::string lower_prog = program_name;
        std::transform(lower_prog.begin(), lower_prog.end(), lower_prog.begin(), ::tolower);
        if (lower_line.find(lower_prog) != std::string::npos) {
            if (std::regex_search(line, m, id_re)) {
                return m[1].str();
            }
        }
    }
    return program_name;
}

inline bool reinstall_program(const std::string& winget_id) {
    std::string cmd = "winget install --id \"" + winget_id + "\" --accept-package-agreements --accept-source-agreements";
    std::cout << "  " << C::CYAN << t("winget_running", C::WHITE + cmd + C::RESET) << "\n";
    int ret = std::system(cmd.c_str());
    return ret == 0;
}

// Analyzes infected filesystem paths to determine the top-level parent application
// (e.g. Program Files\App -> App) to orchestrate automatic reinstallation.
inline std::vector<std::string> find_affected_programs(const std::vector<std::string>& infected) {
    std::set<std::string> programs;
    static const std::vector<std::string> prog_dirs = {
        "Program Files", "Program Files (x86)", "ProgramData", "AppData"
    };
    for (auto& fpath : infected) {
        fs::path p(fpath);
        auto parts = p.begin();
        while (parts != p.end()) {
            std::string part = parts->string();
            for (auto& d : prog_dirs) {
                if (part == d) {
                    auto next = std::next(parts);
                    if (next != p.end())
                        programs.insert(next->string());
                }
            }
            ++parts;
        }
    }
    return std::vector<std::string>(programs.begin(), programs.end());
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPER: Enable SeDebugPrivilege so we can terminate protected/system processes
// (e.g. svchost.exe running as SYSTEM / PPL-light)
// ═══════════════════════════════════════════════════════════════════════════════
inline bool enable_debug_privilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    LUID luid;
    if (!LookupPrivilegeValueA(nullptr, "SeDebugPrivilege", &luid)) {
        CloseHandle(hToken);
        return false;
    }

    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount           = 1;
    tp.Privileges[0].Luid       = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    bool ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp),
                                    nullptr, nullptr) &&
              GetLastError() == ERROR_SUCCESS;
    CloseHandle(hToken);
    return ok;
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPER: Get environment variable safely
// ═══════════════════════════════════════════════════════════════════════════════
inline std::string get_env(const std::string& var) {
    char* buf = nullptr;
    size_t len = 0;
    if (_dupenv_s(&buf, &len, var.c_str()) == 0 && buf != nullptr) {
        std::string result(buf);
        free(buf);
        return result;
    }
    return "";
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPER: Force-kill all processes matching any of the given names (case-insensitive)
// Automatically enables SeDebugPrivilege to handle SYSTEM/PPL processes like svchost.exe
// ═══════════════════════════════════════════════════════════════════════════════
inline int force_kill_by_name(const std::vector<std::string>& process_names) {
    // Acquire SeDebugPrivilege once before iterating – required for SYSTEM processes
    enable_debug_privilege();

    int killed = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snap, &pe)) {
        do {
            // Convert wide szExeFile to narrow string
            char narrow_name[MAX_PATH] = {};
            WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, narrow_name, sizeof(narrow_name), nullptr, nullptr);
            std::string exe_name(narrow_name);
            std::string exe_lower = exe_name;
            std::transform(exe_lower.begin(), exe_lower.end(), exe_lower.begin(), ::tolower);

            for (auto& target : process_names) {
                std::string target_lower = target;
                std::transform(target_lower.begin(), target_lower.end(), target_lower.begin(), ::tolower);

                if (exe_lower == target_lower) {
                    HANDLE proc = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                    if (proc) {
                        if (TerminateProcess(proc, 1)) {
                            uyari(t("proc_killed_pid", exe_name, std::to_string(pe.th32ProcessID)));
                            killed++;
                        } else {
                            uyari(t("kill_fail", std::to_string(pe.th32ProcessID)));
                        }
                        CloseHandle(proc);
                    } else {
                        uyari(t("kill_fail", std::to_string(pe.th32ProcessID)));
                    }
                    break;
                }
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return killed;
}

// ═══════════════════════════════════════════════════════════════════════════════
// 1. Kill known malware processes + injected host processes
// ═══════════════════════════════════════════════════════════════════════════════
inline int kill_malware_processes() {
    section(t("malware_scan_title"));
    bilgi(t("malware_scanning"));

    std::vector<std::string> targets = Obf::malware_process_names();
    targets.insert(targets.end(), {
        // Injected hosts (will be restarted clean by user)
        "Discord.exe", "DiscordCanary.exe", "DiscordPTB.exe",
        "msedge.exe",
    });

    int killed = force_kill_by_name(targets);

    if (killed > 0) {
        basari(t("malware_killed", std::to_string(killed)));
        Sleep(2000); // Wait for processes to fully exit
    } else {
        basari(t("malware_not_found"));
    }
    return killed;
}

// ═══════════════════════════════════════════════════════════════════════════════
// 2. Remove known dropped payload files
// ═══════════════════════════════════════════════════════════════════════════════
inline int remove_dropped_files() {
    section(t("payload_clean_title"));
    bilgi(t("payload_cleaning"));

    std::string appdata    = get_env("APPDATA");
    std::string progdata   = get_env("PROGRAMDATA");
    std::string temp       = get_env("TEMP");
    std::string localapp   = get_env("LOCALAPPDATA");

    // Get Startup folder
    char startup_buf[MAX_PATH] = {};
    SHGetFolderPathA(nullptr, CSIDL_STARTUP, nullptr, 0, startup_buf);
    std::string startup(startup_buf);

    struct DropGroup {
        std::string base;
        std::vector<std::string> items;
    };

    auto startup_items = Obf::appdata_drops();
    startup_items.push_back("PedoClown666.jpeg");
    startup_items.push_back("TwerkMaster69.jpeg");

    auto temp_items = Obf::vbs_drops();
    temp_items.insert(temp_items.end(), {"chc11", "cps11", "eck11", "eps11", "bccb11", "bppb11"});

    std::vector<DropGroup> groups = {
        { appdata,  Obf::appdata_drops() },
        { progdata, {"ntos", "wkkr.bug", "bungee.boo", "PedoClown666.jpeg",
                     "TwerkMaster69.jpeg", "ntb.dat"} },
        { temp,     temp_items },
        { startup,  startup_items },
    };

    int removed = 0;
    for (auto& g : groups) {
        if (g.base.empty()) continue;
        for (auto& item : g.items) {
            std::string fpath = g.base + "\\" + item;
            if (fs::exists(fpath)) {
                try {
                    bool suspicious = false;
                    // If it's a known malicious name like Berok.exe, it's always suspicious.
                    // But for .vbs/scripts, we check content.
                    auto ext = fs::path(fpath).extension().string();
                    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

                    if (ext == ".exe" || ext == ".dll") {
                        suspicious = true; // High confidence for these names in Temp/Appdata
                    } else {
                        // Check script content for markers
                        std::ifstream f(fpath);
                        if (f.is_open()) {
                            std::string content((std::istreambuf_iterator<char>(f)),
                                                 std::istreambuf_iterator<char>());
                            f.close();
                            std::string c_lower = content;
                            std::transform(c_lower.begin(), c_lower.end(), c_lower.begin(), ::tolower);

                            if (c_lower.find(Obf::scan_powershell()) != std::string::npos ||
                                c_lower.find(Obf::scan_wscript()) != std::string::npos ||
                                c_lower.find(Obf::marker_domdoc()) != std::string::npos ||
                                c_lower.find(Obf::marker_adodb()) != std::string::npos ||
                                c_lower.find("shell.application") != std::string::npos ||
                                c_lower.find("toggledesktop") != std::string::npos ||
                                c_lower.find(".cy") != std::string::npos || // Common C2 TLD
                                c_lower.find(".sh") != std::string::npos) {
                                suspicious = true;
                            }
                        }
                    }

                    if (suspicious) {
                        fs::remove_all(fpath);
                        uyari(t("hosts_blocked", fpath)); // Uses deleted/blocked alike
                        removed++;
                    }
                } catch (...) {}
            }
        }
    }

    if (removed > 0) basari(t("payload_deleted", std::to_string(removed)));
    else basari(t("payload_not_found"));
    return removed;
}

// ═══════════════════════════════════════════════════════════════════════════════
// 3. Discord Hijack Remediation (Terminates processes, strips profapi.dll and injected JS loaders)
// ═══════════════════════════════════════════════════════════════════════════════
inline int clean_discord() {
    section(t("discord_clean_title"));
    bilgi(t("discord_cleaning"));

    // Force-close Discord first
    bilgi(t("discord_closing"));
    force_kill_by_name({"Discord.exe", "DiscordCanary.exe", "DiscordPTB.exe"});
    Sleep(2000);

    std::string localapp = get_env("LOCALAPPDATA");
    if (localapp.empty()) {
        hata(t("discord_no_localapp"));
        return 0;
    }

    std::vector<std::string> discord_dirs = {
        localapp + "\\Discord",
        localapp + "\\DiscordCanary",
        localapp + "\\DiscordPTB",
    };

    int cleaned = 0;
    for (auto& dir : discord_dirs) {
        if (!fs::exists(dir)) continue;

        try {
            for (auto& entry : fs::directory_iterator(dir)) {
                if (!entry.is_directory()) continue;
                std::string folder_name = entry.path().filename().string();
                if (folder_name.substr(0, 4) != "app-") continue;

                // Check for injected profapi.dll
                std::string dll_path = entry.path().string() + "\\profapi.dll";
                if (fs::exists(dll_path)) {
                    try {
                        fs::remove(dll_path);
                        uyari(t("discord_dll_del", dll_path));
                        cleaned++;
                    } catch (...) {
                        hata(t("discord_dll_err", dll_path));
                    }
                }

                // Also check for suspicious .js injections in resources
                std::string resources_dir = entry.path().string() + "\\resources";
                if (fs::exists(resources_dir)) {
                    try {
                        for (auto& res_entry : fs::recursive_directory_iterator(
                                resources_dir, fs::directory_options::skip_permission_denied)) {
                            if (!res_entry.is_regular_file()) continue;
                            auto ext = res_entry.path().extension().string();
                            if (ext != ".js") continue;

                            std::ifstream f(res_entry.path().string());
                            if (!f.is_open()) continue;
                            std::string content((std::istreambuf_iterator<char>(f)),
                                                 std::istreambuf_iterator<char>());
                            f.close();

                            if (content.find(Obf::marker_vcclib()) != std::string::npos ||
                                content.find(Obf::marker_luckyware()) != std::string::npos ||
                                content.find(Obf::marker_wfkuuv()) != std::string::npos) {
                                try {
                                    fs::remove(res_entry.path());
                                    uyari(t("discord_js_del", res_entry.path().string()));
                                    cleaned++;
                                } catch (...) {}
                            }
                        }
                    } catch (...) {}
                }
            }
        } catch (...) {}
    }

    if (cleaned > 0) basari(t("discord_clean_done", std::to_string(cleaned)));
    else basari(t("discord_already_clean"));
    return cleaned;
}

// ═══════════════════════════════════════════════════════════════════════════════
// 4. Edge Policy/Data Sanitization (Removes hijacked policy directories from Edge User Data)
// ═══════════════════════════════════════════════════════════════════════════════
inline int clean_edge() {
    section(t("edge_clean_title"));
    bilgi(t("edge_cleaning"));

    std::string localapp = get_env("LOCALAPPDATA");
    if (localapp.empty()) return 0;

    std::string edge_data = localapp + "\\Microsoft\\Edge\\User Data";
    if (!fs::exists(edge_data)) {
        basari(t("edge_no_data"));
        return 0;
    }

    std::vector<std::string> hijack_folders = {
        "Domain Actions", "Well Known Domains"
    };

    int cleaned = 0;
    for (auto& folder : hijack_folders) {
        std::string target = edge_data + "\\" + folder;
        if (fs::exists(target)) {
            try {
                fs::remove_all(target);
                uyari(t("edge_hijack_del", target));
                cleaned++;
            } catch (...) {
                hata(t("edge_hijack_err", target));
            }
        }
    }

    if (cleaned > 0) basari(t("edge_clean_done", std::to_string(cleaned)));
    else basari(t("edge_already_clean"));
    return cleaned;
}

// ═══════════════════════════════════════════════════════════════════════════════

// FULL CLEAN: Runs every cleanup module in the correct order
// ═══════════════════════════════════════════════════════════════════════════════
inline void full_clean() {
    section(t("full_clean_title"));
    bilgi(t("full_clean_starting"));

    kill_malware_processes();
    remove_dropped_files();
    clean_discord();
    clean_edge();
    clean_sdk();
    clean_imgui();
    clean_registry();
    update_hosts();
    empty_temp_folders();

    std::cout << "\n";
    basari(t("full_clean_done"));
}

} // namespace Cleaner

