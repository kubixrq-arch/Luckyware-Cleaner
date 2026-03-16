#pragma once
// Luckyware Cleaner - Cleaner Module
// Handles: VCXPROJ, SUO, SDK (windows.h), ImGui, HOSTS, Registry, Winget reinstall
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
#include "ui.hpp"
#include "lang.hpp"

namespace Cleaner {

namespace fs = std::filesystem;
using namespace UI;
using namespace Lang;

// Removes the entire <PreBuildEvent>...</PreBuildEvent> block from a .vcxproj file.
// Uses regex with icase so tag casing variations are covered.
inline bool clean_vcxproj(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return false;
    std::string content((std::istreambuf_iterator<char>(f)),
                         std::istreambuf_iterator<char>());
    f.close();

    std::regex prebuild_block(
        R"(\s*<PreBuildEvent>[\s\S]*?<\/PreBuildEvent>\s*)",
        std::regex::icase
    );
    bool changed = false;
    std::string new_content = content;

    if (std::regex_search(content, prebuild_block)) {
        new_content = std::regex_replace(new_content, prebuild_block, "\n");
        uyari("<PreBuildEvent> bloğu komple silindi: " + path);
        changed = true;
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
        hata(std::string("SUO silinemedi: ") + e.what());
        return false;
    }
}

// Scans all windows.h files under Windows Kits directories and removes the
// injected `namespace VccLibaries { ... } // namespace VccLibaries` block.
inline std::vector<std::string> clean_sdk() {
    section(t("sdk_title"));
    bilgi(t("sdk_cleaning"));

    std::vector<std::string> cleaned;
    std::regex vcc_block(
        R"(namespace\s+VccLibaries\s*\{[\s\S]*?\}\s*//\s*namespace\s+VccLibaries[^\n]*\n?)",
        std::regex::icase
    );
    std::regex vcc_check(R"(namespace\s+VccLibaries)", std::regex::icase);

    std::vector<std::string> sdk_roots = {
        "C:\\Program Files (x86)\\Windows Kits\\10\\Include",
        "C:\\Program Files\\Windows Kits\\10\\Include",
    };

    for (auto& root : sdk_roots) {
        if (!fs::exists(root)) continue;
        try {
            for (auto& entry : fs::recursive_directory_iterator(root,
                    fs::directory_options::skip_permission_denied)) {
                if (!entry.is_regular_file()) continue;
                if (entry.path().filename().string() != "windows.h") continue;

                std::string fpath = entry.path().string();
                std::ifstream rf(fpath);
                if (!rf.is_open()) continue;
                std::string content((std::istreambuf_iterator<char>(rf)),
                                     std::istreambuf_iterator<char>());
                rf.close();

                if (!std::regex_search(content, vcc_check)) continue;

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

// Deletes all files/directories inside %TEMP% and %TMP%.
// Locked files are silently skipped.
inline void empty_temp_folders() {
    section("TEMP KLASÖRÜ TEMİZLİĞİ");
    bilgi("Geçici dosyalar (%TEMP% ve %TMP%) temizleniyor...");

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
        basari(std::to_string(deleted_count) + " geçici dosya/klasör kalıcı olarak silindi.");
    } else {
        basari("Temp klasörleri zaten temizdi.");
    }
    if (skipped_count > 0) {
        uyari(std::to_string(skipped_count) + " dosya kilitli olduğu için atlandi (reboot sonrası silinebilir).");
    }
}


// Removes Luckyware payload lines from imgui_impl_win32.cpp files found under
// C:\Users, C:\Program Files, and C:\Program Files (x86).
// Three pattern types are removed:
//   1. std::string F<ID> = "\x...\x..."; (hex-encoded payload)
//   2. system(F<ID>.c_str());
//   3. // Luckyware <comment>
inline std::vector<std::string> clean_imgui(const std::string& search_root = "C:\\Users") {
    section(t("imgui_title"));

    std::vector<std::regex> patterns = {
        std::regex(R"(^\s*std::string\s+F[a-zA-Z0-9]+\s*=\s*"(?:\\x[0-9a-fA-F]{2})+";\s*$)"),
        std::regex(R"(^\s*system\(F[a-zA-Z0-9]+\.c_str\(\)\)\s*;\s*$)"),
        std::regex(R"(\s*//\s*Luckyware[^\n]*\n?)"),
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

                if (content.find("VccLibaries") == std::string::npos &&
                    content.find("system(F") == std::string::npos) continue;

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

// Appends missing Luckyware C2 domains as `0.0.0.0 <domain>` entries in the HOSTS file.
// Default domain list mirrors the known Luckyware C2 infrastructure.
inline int update_hosts(std::vector<std::string> domains = {
    "i-like.boats", "krispykreme.top", "nuzzyservices.com",
    "devruntime.cy", "luckyware.co", "bounty-valorant.lol",
    "vcc-redistrbutable.help"
}) {
    if (domains.empty()) return 0;
    section(t("hosts_title"));
    bilgi("C2 domainleri HOSTS dosyasina engelleniyor...");

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
            uyari("HOSTS engeli eklendi: " + dom);
            added++;
        }
    }
    wf.close();

    if (added > 0) basari(std::to_string(added) + " yeni C2 domaini engellendi.");
    else basari("Engellenmesi gereken yeni domain yok, hepsi guvende.");

    return added;
}

// Scans HKCU and HKLM Run/RunOnce keys for Luckyware-related entries and deletes them.
// Two-pass approach: collect targets first, then delete (avoids index corruption during enumeration).
inline int clean_registry() {
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

// Queries `winget list --name <program>` and extracts the Publisher.AppName ID
// from the output. Falls back to the raw program name if parsing fails.
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
    std::cout << "  " << C::CYAN << "Çalıştırılıyor: " << C::WHITE << cmd << C::RESET << "\n";
    int ret = std::system(cmd.c_str());
    return ret == 0;
}

// Walks infected file paths and extracts top-level directory names under well-known
// program directories (Program Files, AppData, etc.) as "affected program" names.
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

} // namespace Cleaner
