#pragma once
// Luckyware Cleaner - Console UI
// ANSI colors, logging helpers, typing effect, ASCII art, toast notification,
// animated banner, progress bar with gradient, spinner, language selector.
#include <string>
#include <iostream>
#include <sstream>
#include <chrono>
#include <thread>
#include <atomic>
#include <iomanip>
#include <vector>
#include <windows.h>
#include <mutex>
#include "lang.hpp"

namespace UI {

using namespace Lang;

inline std::mutex console_mutex;

namespace C {
    inline const std::string RESET   = "\033[0m";
    inline const std::string RED     = "\033[91m";
    inline const std::string GREEN   = "\033[92m";
    inline const std::string YELLOW  = "\033[93m";
    inline const std::string BLUE    = "\033[94m";
    inline const std::string MAGENTA = "\033[95m";
    inline const std::string CYAN    = "\033[96m";
    inline const std::string WHITE   = "\033[97m";
    inline const std::string BRED    = "\033[1;91m";
    inline const std::string BWHITE  = "\033[1;97m";
    inline const std::string DIM     = "\033[2m";
}

// Enables ANSI escape code processing on Windows 10+ and sets the console to UTF-8.
inline void enable_ansi() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) return;
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
}

inline void set_title(const std::string& title) {
    SetConsoleTitleA(title.c_str());
}

inline void bilgi(const std::string& msg) {
    std::lock_guard<std::mutex> lock(console_mutex);
    std::cout << "\033[2K\r  " << C::CYAN << "[+]" << C::RESET << " " << msg << "\n";
}
inline void uyari(const std::string& msg) {
    std::lock_guard<std::mutex> lock(console_mutex);
    std::cout << "\033[2K\r  " << C::YELLOW << "[!]" << C::RESET << " " << msg << "\n";
}
inline void hata(const std::string& msg) {
    std::lock_guard<std::mutex> lock(console_mutex);
    std::cout << "\033[2K\r  " << C::RED << "[-]" << C::RESET << " " << msg << "\n";
}
inline void basari(const std::string& msg) {
    std::lock_guard<std::mutex> lock(console_mutex);
    std::cout << "\033[2K\r  " << C::GREEN << "[✓]" << C::RESET << " " << msg << "\n";
}
inline void tehdit(const std::string& msg) {
    std::lock_guard<std::mutex> lock(console_mutex);
    std::cout << "\033[2K\r  " << C::BRED << "[⚠]" << C::RESET << " " << C::RED << msg << C::RESET << "\n";
}
inline void yatay_cizgi(const std::string& ch = "-", int n = 60) {
    std::lock_guard<std::mutex> lock(console_mutex);
    std::cout << "\033[2K\r  " << C::CYAN;
    for (int i = 0; i < n; ++i) std::cout << ch;
    std::cout << C::RESET << "\n";
}
inline void section(const std::string& title) {
    std::lock_guard<std::mutex> lock(console_mutex);
    std::cout << "\n\033[2K\r  " << C::CYAN;
    for (int i = 0; i < 56; ++i) std::cout << "\u2501";
    std::cout << C::RESET << "\n\033[2K\r  " << C::WHITE << "  " << title << "\n\033[2K\r  " << C::CYAN;
    for (int i = 0; i < 56; ++i) std::cout << "\u2501";
    std::cout << C::RESET << "\n\n";
}

inline void type_text(const std::string& text, int delay_ms = 15) {
    for (char c : text) {
        std::cout << c << std::flush;
        std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
    }
}

inline void print_shield() {
    std::cout << C::GREEN << R"(
      ██████████████
    ██              ██
  ██   ╔══════════╗   ██
  ██   ║  ✓ SAFE  ║   ██
  ██   ╚══════════╝   ██
    ██              ██
      ██          ██
        ██      ██
          ██  ██
            ██
)" << C::RESET;
}

inline void print_skull() {
    std::cout << C::RED << R"(
        ██████████
      ██          ██
    ██   ██    ██   ██
    ██              ██
      ██  ██████  ██
        ██      ██
      ██ ██ ██ ██ ██
        ██████████
           ████
           ████
)" << C::RESET;
}

inline void print_scan_result(int threats, int yara_hits, int files_scanned, double elapsed_sec) {
    std::cout << "\n";
    if (threats == 0 && yara_hits == 0) {
        print_shield();
        std::cout << "  " << C::GREEN;
        type_text("  SISTEM TEMIZ — Hicbir tehdit bulunamadi!", 20);
        std::cout << C::RESET << "\n";
    } else {
        print_skull();
        std::cout << "  " << C::RED;
        type_text("  TEHDIT TESPIT EDILDI — Temizleme onerilir!", 20);
        std::cout << C::RESET << "\n";
    }
    int mins = static_cast<int>(elapsed_sec) / 60;
    int secs = static_cast<int>(elapsed_sec) % 60;
    std::cout << "\n  " << C::CYAN << "╔═══════════════════════════════════╗" << C::RESET;
    std::cout << "\n  " << C::CYAN << "║" << C::WHITE << "  Taranan Dosya  : " << C::YELLOW << std::setw(10) << files_scanned << "   " << C::CYAN << "   ║" << C::RESET;
    std::cout << "\n  " << C::CYAN << "║" << C::WHITE << "  Tehdit         : " << (threats > 0 ? C::RED : C::GREEN) << std::setw(10) << threats << "   " << C::CYAN << "   ║" << C::RESET;
    std::cout << "\n  " << C::CYAN << "║" << C::WHITE << "  YARA Eslesmesi : " << (yara_hits > 0 ? C::RED : C::GREEN) << std::setw(10) << yara_hits << "   " << C::CYAN << "   ║" << C::RESET;
    std::cout << "\n  " << C::CYAN << "║" << C::WHITE << "  Sure           : " << C::GREEN << std::setw(7) << mins << ":" << std::setfill('0') << std::setw(2) << secs << std::setfill(' ') << "" << C::CYAN << "      ║" << C::RESET;
    std::cout << "\n  " << C::CYAN << "╚═══════════════════════════════════╝" << C::RESET << "\n\n";
}

// Fires a Windows 10/11 toast notification via PowerShell WinRT APIs.
// The process is launched detached (CREATE_NO_WINDOW) so it doesn't block the UI.
inline void toast_notify(const std::string& title, const std::string& message) {
    std::string ps_cmd = "powershell -Command \"$null = [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]; "
        "$null = [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom, ContentType = WindowsRuntime]; "
        "$xml = [Windows.Data.Xml.Dom.XmlDocument]::new(); "
        "$xml.LoadXml('<toast><visual><binding template=\\\"ToastText02\\\"><text id=\\\"1\\\">"
        + title + "</text><text id=\\\"2\\\">"
        + message + "</text></binding></visual></toast>'); "
        "$toast = [Windows.UI.Notifications.ToastNotification]::new($xml); "
        "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('LuckywareCleaner').Show($toast)\"";
    STARTUPINFOA si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {};
    std::string cmd = "cmd.exe /c " + ps_cmd;
    CreateProcessA(NULL, const_cast<char*>(cmd.c_str()), NULL, NULL, FALSE,
                   CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    if (pi.hThread) CloseHandle(pi.hThread);
    if (pi.hProcess) CloseHandle(pi.hProcess);
}

inline void print_banner(bool animate = true) {
    std::string subtitle = t("banner_subtitle");

    std::vector<std::string> banner_lines = {
        "  ██╗     ██╗   ██╗ ██████╗██╗  ██╗██╗   ██╗██╗    ██╗ █████╗ ██████╗ ███████╗",
        "  ██║     ██║   ██║██╔════╝██║ ██╔╝╚██╗ ██╔╝██║    ██║██╔══██╗██╔══██╗██╔════╝",
        "  ██║     ██║   ██║██║     █████╔╝  ╚████╔╝ ██║ █╗ ██║███████║██████╔╝█████╗  ",
        "  ██║     ██║   ██║██║     ██╔═██╗   ╚██╔╝  ██║███╗██║██╔══██║██╔══██╗██╔══╝  ",
        "  ███████╗╚██████╔╝╚██████╗██║  ██╗   ██║   ╚███╔███╔╝██║  ██║██║  ██║███████╗",
        "  ╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝   ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝",
    };

    std::cout << "\n";
    for (auto& line : banner_lines) {
        std::cout << C::RED << line << C::RESET << "\n";
        if (animate) std::this_thread::sleep_for(std::chrono::milliseconds(60));
    }

    std::cout << C::CYAN << "  ╔══════════════════════════════════════════════════════════════════════╗\n";
    if (animate) std::this_thread::sleep_for(std::chrono::milliseconds(30));
    std::cout << "  ║  " << C::WHITE << std::left << std::setw(68) << (subtitle + "  \u2500  ") << C::CYAN << "     ║\n";
    if (animate) std::this_thread::sleep_for(std::chrono::milliseconds(30));
    std::cout << "  ║  " << C::BLUE << std::setw(68) << "Developer: victus & ziyy  |  C++ Edition" << C::CYAN << "║\n";
    if (animate) std::this_thread::sleep_for(std::chrono::milliseconds(30));
    std::cout << "  ║  " << C::BLUE << std::setw(68) << "github.com/SkyKubi0" << C::CYAN << "║\n";
    if (animate) std::this_thread::sleep_for(std::chrono::milliseconds(30));
    std::cout << "  ╚══════════════════════════════════════════════════════════════════════╝" << C::RESET << "\n\n";
}

class ProgressBar {
public:
    int total;
    std::atomic<int> current{0};
    std::atomic<int> threats{0};
    std::atomic<int> yara_hits{0};
    std::chrono::steady_clock::time_point start_time;
    int bar_width = 40;

    explicit ProgressBar(int total_) : total(total_),
        start_time(std::chrono::steady_clock::now()) {}

    void update(int n = 1) {
        current.fetch_add(n, std::memory_order_relaxed);
        render();
    }

    void render() {
        std::lock_guard<std::mutex> lock(console_mutex);
        int cur = current.load();
        if (total == 0) return;
        double pct = static_cast<double>(cur) / total;
        int filled = static_cast<int>(bar_width * pct);

        auto now = std::chrono::steady_clock::now();
        double elapsed = std::chrono::duration<double>(now - start_time).count();
        double speed = (elapsed > 0) ? cur / elapsed : 0;
        double remaining = (speed > 0) ? (total - cur) / speed : 0;
        int min = static_cast<int>(remaining) / 60;
        int sec = static_cast<int>(remaining) % 60;

        // Gradient: red (0%) → yellow (50%) → green (100%)
        auto gradient_color = [](double ratio) -> std::string {
            if (ratio < 0.5) {
                int g = static_cast<int>(255 * (ratio * 2));
                return "\033[38;2;255;" + std::to_string(g) + ";0m";
            } else {
                int r = static_cast<int>(255 * (1.0 - (ratio - 0.5) * 2));
                return "\033[38;2;" + std::to_string(r) + ";255;0m";
            }
        };

        std::ostringstream bar;
        bar << "  ";
        for (int i = 0; i < filled; ++i) {
            double ratio = static_cast<double>(i) / bar_width;
            bar << gradient_color(ratio) << "\u2588";
        }
        for (int i = filled; i < bar_width; ++i) bar << "\033[90m" << "\u2591";
        bar << C::RESET
            << " " << C::WHITE << std::fixed << std::setprecision(1) << (pct * 100) << "%"
            << C::RESET << " " << C::YELLOW << cur << "/" << total << C::RESET
            << " ETA:" << C::GREEN << std::setw(2) << std::setfill('0') << min << ":"
            << std::setw(2) << sec << C::RESET
            << " TEHDIT:" << C::RED << threats.load() << C::RESET
            << " YARA:" << C::YELLOW << yara_hits.load() << C::RESET
            << "   ";

        std::cout << "\033[2K\r" << bar.str() << std::flush;

        if (cur % 500 == 0 || cur == total) {
            set_title(t("title_scanning", std::to_string(cur) + "/" + std::to_string(total)));
        }
    }

    void finish() {
        std::cout << "\n";
        set_title(t("title_idle"));
    }
};

class Spinner {
    std::atomic<bool> running{false};
    std::thread th;
    std::string msg;
public:
    explicit Spinner(const std::string& m) : msg(m) {}
    void start() {
        running = true;
        th = std::thread([this]() {
            const char* frames[] = {"|", "/", "-", "\\"};
            int i = 0;
            while (running) {
                {
                    std::lock_guard<std::mutex> lock(console_mutex);
                    std::cout << "\033[2K\r  " << C::CYAN << frames[i % 4] << C::RESET
                              << " " << msg << "   " << std::flush;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(120));
                ++i;
            }
        });
    }
    void stop() {
        running = false;
        if (th.joinable()) th.join();
        std::lock_guard<std::mutex> lock(console_mutex);
        std::cout << "\033[2K\r" << std::flush;
    }
};

inline void select_language() {
    std::cout << "\n";
    yatay_cizgi("\u2501", 56);
    std::cout << "  " << C::WHITE << "  🌐 LANGUAGE / DİL\n";
    yatay_cizgi("\u2501", 56);
    std::cout << "  " << C::WHITE << "  [1] " << C::GREEN << "Türkçe (TR)\n";
    std::cout << "  " << C::WHITE << "  [2] " << C::CYAN << "English (EN)\n";
    yatay_cizgi("\u2501", 56);
    std::cout << "\n  " << C::YELLOW << "➤ " << C::RESET;
    std::string inp;
    std::getline(std::cin, inp);
    Lang::set_lang(inp);
    std::cout << "\n";
}

// good_if_zero=true  → green when count==0 (e.g. threats)
// good_if_zero=false → green when count>0  (e.g. files scanned)
inline void print_result_row(const std::string& label, int count, bool good_if_zero = true) {
    bool good = good_if_zero ? (count == 0) : (count > 0);
    std::string val_color = good ? C::GREEN : C::RED;
    std::string suffix = good ? " \u2713" : " \u26a0";
    std::cout << "  " << C::WHITE << "  \u251c\u2500 "
              << std::left << std::setw(28) << label << ": "
              << val_color << count << suffix << C::RESET << "\n";
}
inline void print_result_row_last(const std::string& label, int count, bool good_if_zero = true) {
    bool good = good_if_zero ? (count == 0) : (count > 0);
    std::string val_color = good ? C::GREEN : C::RED;
    std::string suffix = good ? " \u2713" : " \u26a0";
    std::cout << "  " << C::WHITE << "  \u2514\u2500 "
              << std::left << std::setw(28) << label << ": "
              << val_color << count << suffix << C::RESET << "\n";
}

} // namespace UI
