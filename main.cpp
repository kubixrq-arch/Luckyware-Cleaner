#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <windows.h>
#include <shlobj.h>     // IsUserAnAdmin
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <vector>
#include <map>
#include <iostream>
#include <algorithm>
#include <filesystem>

#include "ui.hpp"
#include "lang.hpp"
#include "yara_engine.hpp"
#include "pe_check.hpp"
#include "scanner.hpp"
#include "detector.hpp"
#include "cleaner.hpp"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "shell32.lib")

namespace fs = std::filesystem;
using namespace UI;
using namespace Lang;

struct Args {
    std::string scan_path;
    std::string rules_path = "rules\\luckyware.yar";
    bool block_c2      = false;
    bool auto_clean    = false;
    bool patch_pe      = false;
    bool kill_process  = false;
    bool skip_registry = false;
    bool debug         = false;
    bool clear_cache   = false;
    std::string lang   = "";

    // Cleaner-mode flags (active when no scan_path is given)
    bool unblock             = false;
    bool clean_registry_flag = false;
    bool clean_sdk_flag      = false;
    bool clean_imgui_flag    = false;
};

inline bool is_admin() {
    BOOL result = FALSE;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    PSID adminGroup = nullptr;
    if (AllocateAndInitializeSid(&ntAuth, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(nullptr, adminGroup, &result);
        FreeSid(adminGroup);
    }
    return result == TRUE;
}

inline Args parse_args(int argc, char* argv[]) {
    Args args;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--block" || a == "--engelle")              args.block_c2 = true;
        else if (a == "--remove" || a == "--temizle")        args.auto_clean = true;
        else if (a == "--patch-pe" || a == "--yama-pe")      args.patch_pe = true;
        else if (a == "--kill-process" || a == "--oldur")    args.kill_process = true;
        else if (a == "--skip-registry" || a == "--registry-atla") args.skip_registry = true;
        else if (a == "--debug" || a == "--hata-ayikla")     args.debug = true;
        else if (a == "--clear-cache" || a == "--cache-temizle") args.clear_cache = true;
        else if (a == "--unblock")                           args.unblock = true;
        else if (a == "--clean-registry")                    args.clean_registry_flag = true;
        else if (a == "--clean-sdk")                         args.clean_sdk_flag = true;
        else if (a == "--clean-imgui")                       args.clean_imgui_flag = true;
        else if ((a == "--rules" || a == "--kurallar") && i + 1 < argc)
            args.rules_path = argv[++i];
        else if ((a == "--lang" || a == "--dil") && i + 1 < argc)
            args.lang = argv[++i];
        else if (a[0] != '-' && args.scan_path.empty())
            args.scan_path = a;
    }
    return args;
}

// Searches several candidate paths for the YARA rules file.
inline std::string find_rules(const std::string& rules_hint) {
    std::vector<std::string> candidates = {
        rules_hint,
        fs::path(rules_hint).filename().string(),
        "rules\\luckyware.yar",
        "..\\rules\\luckyware.yar",
    };
    for (auto& c : candidates) {
        if (fs::exists(c)) return c;
    }
    return "";
}

int main(int argc, char* argv[]) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    enable_ansi();
    print_banner();

    Args args = parse_args(argc, argv);

    try {
        if (!args.lang.empty()) {
            set_lang(args.lang);
        } else {
            if (argc <= 1) {
                select_language();
            }
        }

        if (is_admin()) {
            basari(t("admin_ok"));
        } else {
            uyari(t("admin_required"));
            // Some features (HOSTS, registry, process kill) require elevation.
        }

        std::cout << "\n";

        if (args.clear_cache) {
            Scanner::clear_cache();
        }

        // -------------------------------------------------------
        // CLEANER MODE: run standalone cleanup without a scan path
        // -------------------------------------------------------
        if (args.scan_path.empty() && (args.unblock || args.clean_registry_flag ||
            args.clean_sdk_flag || args.clean_imgui_flag)) {

            if (args.unblock)               Cleaner::update_hosts();
            if (args.clean_registry_flag)   Cleaner::clean_registry();
            if (args.clean_sdk_flag)        Cleaner::clean_sdk();
            if (args.clean_imgui_flag)      Cleaner::clean_imgui();

            WSACleanup();
            std::cout << "\n";
            bilgi(t("press_enter"));
            std::cin.get();
            return 0;
        }

        // -------------------------------------------------------
        // SCAN MODE
        // -------------------------------------------------------
        if (args.scan_path.empty()) {
            if (argc <= 1) {
                std::cout << "\n  " << C::YELLOW << "➤ " << C::WHITE
                          << t("enter_scan_path") << C::RESET;
                std::getline(std::cin, args.scan_path);

                // Strip surrounding quotes that Windows drag-and-drop may add
                if (!args.scan_path.empty()) {
                    if (args.scan_path.front() == '"') args.scan_path.erase(0, 1);
                    if (args.scan_path.back() == '"') args.scan_path.pop_back();
                }

                if (args.scan_path.empty()) {
                    std::cout << "\n";
                    bilgi(t("press_enter"));
                    std::cin.get();
                    WSACleanup();
                    return 1;
                }
            } else {
                hata(t("no_scan_path"));
                std::cout << "  LuckywareCleaner.exe C:\\ --rules rules\\luckyware.yar [seçenekler]\n";
                std::cout << "\nSeçenekler:\n";
                std::cout << "  --block           C2 domainlerini HOSTS'a engelle\n";
                std::cout << "  --remove          Enfekte dosyaları otomatik temizle\n";
                std::cout << "  --patch-pe        Zararlı PE bölümlerini patch'le\n";
                std::cout << "  --kill-process    Zararlı süreçleri sonlandır\n";
                std::cout << "  --unblock         HOSTS'tan Luckyware engellerini kaldır\n";
                std::cout << "  --clean-registry  Registry'den zararlı Run kayıtlarını sil\n";
                std::cout << "  --clean-sdk       windows.h'dan VccLibaries'i kaldır\n";
                std::cout << "  --clean-imgui     imgui_impl_win32.cpp'den hex payload'ı kaldır\n";
                std::cout << "  --rules <dosya>   YARA kural dosyası (varsayılan: rules\\luckyware.yar)\n";
                std::cout << "  --lang tr|en      Dil seçimi\n";
                std::cout << "  --clear-cache     SHA256 cache'i temizle\n";
                std::cout << "  --debug           Hata ayıklama modu\n";
                WSACleanup();
                return 1;
            }
        }

        if (!fs::exists(args.scan_path)) {
            hata("Tarama yolu bulunamadı: " + args.scan_path);
            if (argc <= 1) {
                std::cout << "\n";
                bilgi(t("press_enter"));
                std::cin.get();
            }
            WSACleanup();
            return 1;
        }

        std::string rules_file = find_rules(args.rules_path);
        if (rules_file.empty()) {
            uyari(t("rule_missing", args.rules_path));
            // Scanning continues with PE/pattern checks only (no YARA)
        } else {
            bilgi(t("rule_found", rules_file));
        }

        std::vector<YaraEngine::YaraRule> rules;
        if (!rules_file.empty()) {
            rules = YaraEngine::load_rules(rules_file);
            bilgi(t("scan_yara_loaded",
                   rules_file + " (" + std::to_string(rules.size()) + " kural)"));
        }
        std::cout << "\n";

        // Extract C2 domains from rules so they are available for blocking/interactive mode
        std::vector<std::string> c2_domains;
        if (!rules.empty()) {
            c2_domains = YaraEngine::extract_domains(rules);
        }

        if (args.block_c2 && !c2_domains.empty()) {
            uyari(t("blocking_c2"));
            Detector::block_domains(c2_domains);
            std::cout << "\n";
        }

        set_title(t("title_idle"));

        bilgi(t("scan_starting", args.scan_path));
        bilgi(t("scan_extensions", ".exe, .dll, .suo, .vcxproj"));

        Scanner::ScanOptions scan_opts;
        scan_opts.auto_clean   = args.auto_clean;
        scan_opts.patch_pe     = args.patch_pe;
        scan_opts.debug        = args.debug;
        scan_opts.num_threads  = 8;

        auto scan_start_time = std::chrono::steady_clock::now();
        auto scan_result = Scanner::scan_directory(args.scan_path, rules, scan_opts);
        auto& infected = scan_result.infected_files;
        auto& counters = scan_result.counters;

        std::cout << "\n";
        yatay_cizgi("\u2501", 56);
        std::cout << "  " << C::WHITE << "  " << t("scan_done_title") << "\n";
        yatay_cizgi("\u2501", 56);
        std::cout << "  " << C::WHITE << "  \u251c\u2500 " << std::left << std::setw(28)
                  << t("scan_total") << ": " << C::CYAN << counters.total << C::RESET << "\n";
        std::cout << "  " << C::WHITE << "  \u251c\u2500 " << std::setw(28)
                  << t("scan_scanned") << ": " << C::CYAN << counters.scanned << C::RESET << "\n";
        std::cout << "  " << C::WHITE << "  \u251c\u2500 " << std::setw(28)
                  << t("scan_cached") << ": " << C::GREEN << counters.cached << C::RESET << "\n";
        std::cout << "  " << C::WHITE << "  \u251c\u2500 " << std::setw(28)
                  << t("scan_yara_matches") << ": " << C::YELLOW << counters.yara_hits << C::RESET << "\n";
        std::cout << "  " << C::WHITE << "  \u251c\u2500 " << std::setw(28)
                  << t("scan_confirmed") << ": " << C::RED << counters.confirmed << C::RESET << "\n";
        std::cout << "  " << C::WHITE << "  \u2514\u2500 " << std::setw(28)
                  << t("scan_false_pos") << ": " << C::GREEN << counters.false_pos << C::RESET << "\n";
        yatay_cizgi("\u2501", 56);

        if (!infected.empty())
            Scanner::save_report(infected);

        // -------------------------------------------------------
        // ADVANCED DETECTIONS
        // -------------------------------------------------------
        std::map<DWORD, std::string> all_malicious_pids;

        auto mutex_res = Detector::mutex_scan();
        for (auto& [pid, name] : mutex_res.malicious_pids)
            all_malicious_pids[pid] = name;

        auto loader_res = Detector::loader_scan();
        for (auto& pi : loader_res.found)
            all_malicious_pids[pi.pid] = pi.name;

        auto hollow_res = Detector::hollow_scan();
        for (auto& pi : hollow_res.found) {
            if (pi.pid > 0) all_malicious_pids[pi.pid] = pi.name;
        }

        section(t("sdk_title"));
        basari(t("sdk_clean"));

        if (!rules.empty()) {
            auto c2_domains = YaraEngine::extract_domains(rules);
            auto c2_result = Detector::github_c2_check(c2_domains);
            if (!c2_result.found_domains.empty()) {
                tehdit("AKTİF C2 DOMAIN: " + std::to_string(c2_result.found_domains.size()) + " domain engellenmemiş!");
            } else {
                basari("C2 domainleri engelli ✓");
            }
        }

        auto dns_res = Detector::dns_bypass_scan();
        for (auto& pi : dns_res.found)
            all_malicious_pids[pi.pid] = pi.name;

        if (!args.skip_registry) {
            auto reg_res = Detector::registry_scan();
            if (!reg_res.found_keys.empty()) {
                uyari("⚠ " + std::to_string(reg_res.found_keys.size()) + " zararlı registry kaydı bulundu!");
            }
        }

        if (args.kill_process && !all_malicious_pids.empty()) {
            Detector::kill_processes(all_malicious_pids);
        }

        section(t("results_title"));
        print_result_row(t("results_infected"),  (int)infected.size());
        print_result_row(t("results_mutex"),      (int)mutex_res.found_mutexes.size());
        print_result_row("Loader/Hollow",         (int)(loader_res.found.size() + hollow_res.found.size()));
        print_result_row("DNS DoH Bypass",        (int)dns_res.found.size());
        print_result_row_last(t("results_c2"),    0);

        yatay_cizgi("\u2501", 56);
        std::cout << "\n";

        // -------------------------------------------------------
        // OPTIONAL: auto-clean flags passed on command line
        // -------------------------------------------------------
        if (args.auto_clean || args.unblock || args.clean_registry_flag ||
            args.clean_sdk_flag || args.clean_imgui_flag) {

            if (args.clean_registry_flag)   Cleaner::clean_registry();
            if (args.unblock)               Cleaner::update_hosts(c2_domains);
            if (args.clean_sdk_flag)        Cleaner::clean_sdk();
            if (args.clean_imgui_flag)      Cleaner::clean_imgui();

            if (!infected.empty()) {
                auto programs = Cleaner::find_affected_programs(infected);
                if (!programs.empty()) {
                    std::cout << "\n";
                    bilgi("Etkilenen programlar: " + std::to_string(programs.size()));
                    for (auto& prog : programs)
                        bilgi("  - " + prog);

                    std::string ans;
                    std::cout << "  " << C::WHITE << "Winget ile yeniden kurulum yapılsın mı? (e/h): "
                              << C::RESET;
                    std::getline(std::cin, ans);
                    if (ans == "e" || ans == "y" || ans == "evet" || ans == "yes") {
                        for (auto& prog : programs) {
                            std::string winget_id = Cleaner::find_winget_id(prog);
                            bilgi("Yeniden kuruluyor: " + winget_id);
                            Cleaner::reinstall_program(winget_id);
                        }
                    }
                }
            }
        }

        int total_threats = (int)infected.size() + (int)mutex_res.found_mutexes.size()
                          + (int)loader_res.found.size() + (int)hollow_res.found.size()
                          + (int)dns_res.found.size();
        double elapsed_sec = std::chrono::duration<double>(
            std::chrono::steady_clock::now() - scan_start_time).count();

        print_scan_result(total_threats, counters.yara_hits, counters.scanned, elapsed_sec);

        if (total_threats > 0) {
            toast_notify("Luckyware Cleaner", std::to_string(total_threats) + " tehdit tespit edildi!");
        } else {
            toast_notify("Luckyware Cleaner", "Sistem temiz - Tehdit bulunamadi!");
        }

        if (total_threats > 0) {
            if (argc <= 1) {
                std::string ans;
                std::cout << "  " << C::WHITE << t("ask_clean_interactive") << C::RESET;
                std::getline(std::cin, ans);

                if (ans == "e" || ans == "y" || ans == "evet" || ans == "yes" || ans == "E" || ans == "Y") {
                    std::cout << "\n";

                    for (const auto& file : infected) {
                        try {
                            if (fs::exists(file)) {
                                std::string ext = fs::path(file).extension().string();
                                std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

                                if (ext == ".vcxproj") {
                                    Cleaner::clean_vcxproj(file);
                                } else if (ext == ".suo") {
                                    Cleaner::clean_suo(file);
                                } else {
                                    fs::remove(file);
                                    bilgi(t("file_deleted_interactive") + file);
                                }
                            }
                        } catch (...) {}
                    }

                    Cleaner::clean_registry();

                    if (!c2_domains.empty()) {
                        Cleaner::update_hosts(c2_domains);
                    }

                    Cleaner::clean_sdk();
                    Cleaner::clean_imgui();
                    Cleaner::empty_temp_folders();

                    if (!all_malicious_pids.empty()) {
                        Detector::kill_processes(all_malicious_pids);
                    }

                    std::cout << "\n  " << C::GREEN;
                    type_text(t("clean_success_interactive"), 15);
                    std::cout << C::RESET << "\n";

                    toast_notify("Luckyware Cleaner", "Temizleme tamamlandi!");
                }
            }
        } else {
            // Tehdit bulunamasa da %TEMP% temizleme seçeneği sun
            if (argc <= 1) {
                std::string ans2;
                std::cout << "\n  " << C::WHITE
                          << "Tehdit bulunamadı. %TEMP% klasörlerini gene de temizlemek ister misiniz? (e/h): "
                          << C::RESET;
                std::getline(std::cin, ans2);
                if (ans2 == "e" || ans2 == "y" || ans2 == "evet" || ans2 == "yes" || ans2 == "E" || ans2 == "Y") {
                    Cleaner::empty_temp_folders();
                }
            }
        }


    } catch (const std::exception& e) {
        std::cout << "\n  \033[31m[!] KRITIK C++ HATASI (CRASH ONLENDI):\033[0m " << e.what() << "\n";
    } catch (...) {
        std::cout << "\n  \033[31m[!] BILINMEYEN BIR HATA OLUSTU!\033[0m\n";
    }

    std::cout << "\n";
    bilgi(t("press_enter"));
    std::cin.get();

    WSACleanup();
    return 0;
}
