#pragma once
// Luckyware Cleaner - File Scanner
// SHA256 cache + thread pool (8 workers by default) + YARA matching + PE section check.
#include <string>
#include <vector>
#include <map>
#include <set>
#include <queue>
#include <mutex>
#include <thread>
#include <future>
#include <atomic>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <filesystem>
#include <functional>
#include <windows.h>
#include <wincrypt.h>
#include "ui.hpp"
#include "lang.hpp"
#include "yara_engine.hpp"
#include "pe_check.hpp"

#pragma comment(lib, "crypt32.lib")

namespace Scanner {

namespace fs = std::filesystem;
using namespace Lang;
using namespace UI;

inline std::string sha256_file(const std::string& filepath) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    std::string result;

    std::ifstream f(filepath, std::ios::binary);
    if (!f.is_open()) return "";

    if (!CryptAcquireContextA(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return "";
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0); return "";
    }

    char buf[8192];
    while (f.read(buf, sizeof(buf)) || f.gcount() > 0) {
        if (!CryptHashData(hHash, reinterpret_cast<BYTE*>(buf), (DWORD)f.gcount(), 0))
            break;
    }

    DWORD hashLen = 32;
    BYTE hashData[32];
    if (CryptGetHashParam(hHash, HP_HASHVAL, hashData, &hashLen, 0)) {
        std::ostringstream oss;
        for (int i = 0; i < 32; ++i)
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)hashData[i];
        result = oss.str();
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return result;
}

// Simple hand-rolled JSON cache for SHA256 results.
// Format: { "path": { "hash": "...", "sonuc": "temiz|enfekte", "tarih": "..." } }
struct CacheEntry {
    std::string hash;
    std::string result; // "temiz" or "enfekte"
    std::string date;
};

using CacheMap = std::map<std::string, CacheEntry>;

inline std::string CACHE_FILE = "luckyware_cache.json";

inline CacheMap load_cache() {
    CacheMap cache;
    std::ifstream f(CACHE_FILE);
    if (!f.is_open()) return cache;

    std::string content((std::istreambuf_iterator<char>(f)),
                         std::istreambuf_iterator<char>());
    f.close();

    std::regex entry_re("\"([^\"]+)\"\\s*:\\s*\\{\\s*\"hash\"\\s*:\\s*\"([^\"]+)\"\\s*,\\s*\"sonuc\"\\s*:\\s*\"([^\"]+)\"\\s*,\\s*\"tarih\"\\s*:\\s*\"([^\"]+)\"\\}");
    auto it = std::sregex_iterator(content.begin(), content.end(), entry_re);
    while (it != std::sregex_iterator()) {
        std::smatch m = *it;
        CacheEntry e;
        e.hash = m[2].str();
        e.result = m[3].str();
        e.date = m[4].str();
        cache[m[1].str()] = e;
        ++it;
    }
    return cache;
}

inline void save_cache(const CacheMap& cache) {
    std::ofstream f(CACHE_FILE);
    f << "{\n";
    bool first = true;
    for (auto& [path, entry] : cache) {
        if (!first) f << ",\n";
        // Escape backslashes and quotes in the path key
        std::string escaped_path;
        for (char c : path) {
            if (c == '\\') escaped_path += "\\\\";
            else if (c == '"') escaped_path += "\\\"";
            else escaped_path += c;
        }
        f << "  \"" << escaped_path << "\": {\"hash\":\"" << entry.hash
          << "\",\"sonuc\":\"" << entry.result
          << "\",\"tarih\":\"" << entry.date << "\"}";
        first = false;
    }
    f << "\n}\n";
}

inline void clear_cache() {
    std::remove(CACHE_FILE.c_str());
    basari("Cache temizlendi.");
}

inline void save_report(const std::vector<std::string>& infected,
                         const std::string& filename = "reports.txt") {
    std::ofstream f(filename);
    for (auto& p : infected) f << p << "\n";
}

struct ScanOptions {
    bool auto_clean   = false;
    bool patch_pe     = false;
    bool debug        = false;
    bool kill_process = false;
    int  num_threads  = 8;
};

// std::atomic members require a custom copy constructor/assignment because
// atomic<T> is not copyable by default.
struct ScanCounters {
    std::atomic<int> total{0};
    std::atomic<int> scanned{0};
    std::atomic<int> cached{0};
    std::atomic<int> yara_hits{0};
    std::atomic<int> confirmed{0};
    std::atomic<int> false_pos{0};

    ScanCounters() = default;
    ScanCounters(const ScanCounters& o) {
        total.store(o.total.load());
        scanned.store(o.scanned.load());
        cached.store(o.cached.load());
        yara_hits.store(o.yara_hits.load());
        confirmed.store(o.confirmed.load());
        false_pos.store(o.false_pos.load());
    }
    ScanCounters& operator=(const ScanCounters& o) {
        if (this != &o) {
            total.store(o.total.load());
            scanned.store(o.scanned.load());
            cached.store(o.cached.load());
            yara_hits.store(o.yara_hits.load());
            confirmed.store(o.confirmed.load());
            false_pos.store(o.false_pos.load());
        }
        return *this;
    }
};

struct ScanResult {
    std::vector<std::string> infected_files;
    ScanCounters counters;
};

inline ScanResult scan_directory(const std::string& root_path,
                                  const std::vector<YaraEngine::YaraRule>& rules,
                                  const ScanOptions& opts = {}) {
    ScanResult result;

    static const std::set<std::string> TARGET_EXT = {
        ".exe", ".dll", ".suo", ".vcxproj"
    };

    // Taranacak tüm kökler: kullanıcının verdiği yol + %TEMP% / %TMP%
    std::vector<std::string> scan_roots = { root_path };
    {
        const char* vars[] = { "TEMP", "TMP" };
        for (const char* v : vars) {
            char* tbuf = nullptr; size_t tlen = 0;
            if (_dupenv_s(&tbuf, &tlen, v) == 0 && tbuf != nullptr) {
                std::string tp(tbuf); free(tbuf);
                if (!tp.empty() && fs::exists(tp)) {
                    std::string tp_lower = tp, root_lower = root_path;
                    std::transform(tp_lower.begin(), tp_lower.end(), tp_lower.begin(), ::tolower);
                    std::transform(root_lower.begin(), root_lower.end(), root_lower.begin(), ::tolower);
                    if (root_lower.find(tp_lower) == std::string::npos &&
                        tp_lower.find(root_lower) == std::string::npos) {
                        bool already = false;
                        for (auto& r : scan_roots) {
                            std::string rl = r;
                            std::transform(rl.begin(), rl.end(), rl.begin(), ::tolower);
                            if (rl == tp_lower) { already = true; break; }
                        }
                        if (!already) scan_roots.push_back(tp);
                    }
                }
            }
        }
    }

    // Tek geçişte hem sayım hem liste (iki ayrı geçiş yerine → daha hızlı)
    set_title(t("title_counting"));
    std::vector<std::string> file_list;
    {
        auto spinner = std::make_unique<Spinner>(t("scan_counting"));
        spinner->start();
        for (auto& scan_root : scan_roots) {
            try {
                for (auto& entry : fs::recursive_directory_iterator(
                    scan_root, fs::directory_options::skip_permission_denied)) {
                    if (!entry.is_regular_file()) continue;
                    auto ext = entry.path().extension().string();
                    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                    if (TARGET_EXT.count(ext)) {
                        file_list.push_back(entry.path().string());
                        result.counters.total.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            } catch (...) {}
        }
        spinner->stop();
    }

    int total_files = (int)file_list.size();
    bilgi(t("scan_total_files", std::to_string(total_files)));

    section(t("scan_in_progress"));
    set_title(t("title_scanning", "0/" + std::to_string(total_files)));

    CacheMap cache = load_cache();
    bool cache_updated = false;
    std::mutex cache_mutex;
    std::mutex result_mutex;
    std::mutex print_mutex;

    if (!cache.empty())
        bilgi(t("scan_cache_loaded", std::to_string(cache.size())));
    else
        bilgi(t("scan_cache_empty"));

    ProgressBar pb(total_files);

    const int NUM_WORKERS = opts.num_threads;
    std::atomic<int> file_idx{0};
    std::vector<std::thread> workers;

    auto get_now_str = []() -> std::string {
        SYSTEMTIME st{};
        GetLocalTime(&st);
        char buf[32];
        snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d",
                 st.wYear, st.wMonth, st.wDay,
                 st.wHour, st.wMinute, st.wSecond);
        return buf;
    };

    auto worker_fn = [&]() {
        while (true) {
            int idx = file_idx.fetch_add(1, std::memory_order_relaxed);
            if (idx >= (int)file_list.size()) break;

            const std::string& filepath = file_list[idx];
            std::string ext;
            {
                auto p = fs::path(filepath).extension().string();
                std::transform(p.begin(), p.end(), p.begin(), ::tolower);
                ext = p;
            }
            bool is_pe = (ext == ".exe" || ext == ".dll");

            // SHA256 mutex DIŞINDA hesaplanır (thread paralelizmi korunur)
            std::string hash = sha256_file(filepath);
            {
                std::lock_guard<std::mutex> lk(cache_mutex);
                if (!hash.empty() && cache.count(filepath)) {
                    auto& ce = cache[filepath];
                    if (ce.hash == hash && ce.result == "temiz") {
                        result.counters.cached.fetch_add(1, std::memory_order_relaxed);
                        pb.update(1);
                        continue;
                    }
                }
            }

            std::vector<YaraEngine::MatchResult> matches;
            try {
                matches = YaraEngine::match_file(filepath, rules);
            } catch (...) {}

            result.counters.scanned.fetch_add(1, std::memory_order_relaxed);

            // Additionally check .vcxproj files for <PreBuildEvent> blocks in case
            // the YARA rule doesn't catch a variant.
            bool is_malicious_vcxproj = false;
            if (ext == ".vcxproj") {
                std::ifstream f(filepath);
                if (f.is_open()) {
                    std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
                    f.close();

                    std::regex prebuild_block(R"(\s*<PreBuildEvent>[\s\S]*?<\/PreBuildEvent>\s*)", std::regex::icase);
                    if (std::regex_search(content, prebuild_block)) {
                        is_malicious_vcxproj = true;
                    }
                }
            }

            if (!matches.empty() || is_malicious_vcxproj) {
                if (!matches.empty()) {
                    result.counters.yara_hits.fetch_add(1, std::memory_order_relaxed);
                    pb.yara_hits.fetch_add(1, std::memory_order_relaxed);
                }

                bool confirmed = false;
                std::string reason;

                if (is_pe) {
                    PECheck::RcdResult rcd = PECheck::check_rcd_sections(filepath);
                    if (rcd.found) {
                        confirmed = true;
                        reason = rcd.reason;
                    } else {
                        result.counters.false_pos.fetch_add(1, std::memory_order_relaxed);
                    }
                } else {
                    confirmed = true;
                    if (!matches.empty()) {
                        reason = "YARA: " + matches[0].rule_name;
                    } else if (ext == ".vcxproj") {
                        reason = "PreBuildEvent zararlı kod enjeksiyonu tespit edildi";
                    } else {
                        reason = "Şüpheli dosya içeriği tespit edildi";
                    }
                }

                if (confirmed) {
                    result.counters.confirmed.fetch_add(1, std::memory_order_relaxed);
                    pb.threats.fetch_add(1, std::memory_order_relaxed);

                    {
                        std::lock_guard<std::mutex> lk(print_mutex);
                        std::cout << "\n";
                        if (!matches.empty()) {
                            for (auto& m : matches)
                                tehdit(m.rule_name + ": " + filepath);
                        } else {
                            tehdit("Şüpheli Yapı Tespit Edildi: " + filepath);
                        }
                        std::cout << "    " << C::RED << "[" << t("scan_infection_confirmed")
                                  << "] " << C::RESET << reason << "\n";
                    }

                    if (is_pe && opts.patch_pe)
                        PECheck::patch_pe_section(filepath);

                    {
                        std::lock_guard<std::mutex> lk(result_mutex);
                        result.infected_files.push_back(filepath);
                    }
                }
            } else {
                if (!hash.empty()) {
                    std::lock_guard<std::mutex> lk(cache_mutex);
                    cache[filepath] = {hash, "temiz", get_now_str()};
                    cache_updated = true;
                }
            }

            pb.update(1);
        }
    };

    workers.reserve(NUM_WORKERS);
    for (int i = 0; i < NUM_WORKERS; ++i)
        workers.emplace_back(worker_fn);
    for (auto& t : workers) t.join();

    pb.finish();

    if (cache_updated)
        save_cache(cache);

    return result;
}

} // namespace Scanner
