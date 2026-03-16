#pragma once
// ============================================================
// Luckyware Cleaner - Dil Sistemi / Language System
// ============================================================
#include <string>
#include <map>
#include <vector>
#include <sstream>

namespace Lang {

inline std::string LANG = "tr";

using TextMap = std::map<std::string, std::map<std::string, std::string>>;

inline TextMap TEXTS = {
    // === Genel / General ===
    {"banner_subtitle",     {{"tr","L U C K Y W A R E   T E M İ Z L E Y İ C İ"},{"en","L U C K Y W A R E   C L E A N E R"}}},
    {"lang_prompt",         {{"tr","Dil seçin / Select language [1=TR / 2=EN]: "},{"en","Select language [1=TR / 2=EN]: "}}},
    {"press_enter",         {{"tr","Çıkmak için Enter..."},{"en","Press Enter to exit..."}}},
    {"enter_scan_path",     {{"tr","Taranacak dosya/klasör yolunu girin (örn: C:\\ veya C:\\Projeler): "},{"en","Enter the path to scan (e.g., C:\\ or C:\\Projects): "}}},
    {"no_scan_path",        {{"tr","Tarama yolu belirtilmedi!"},{"en","Scan path not specified!"}}},

    // === Admin ===
    {"admin_ok",            {{"tr","✓ Yönetici yetkisi onaylandı"},{"en","✓ Administrator privileges confirmed"}}},
    {"admin_required",      {{"tr","⚠ YÖNETİCİ YETKİSİ GEREKLİ! Sağ tık → Yönetici olarak çalıştır"},{"en","⚠ ADMINISTRATOR REQUIRED! Right-click → Run as administrator"}}},

    // === Tarama / Scan ===
    {"scan_counting",       {{"tr","Dosyalar sayılıyor..."},{"en","Counting files..."}}},
    {"scan_total_files",    {{"tr","Toplam hedef dosya: {}"},{"en","Total target files: {}"}}},
    {"scan_in_progress",    {{"tr","DOSYA TARAMASI"},{"en","FILE SCANNING"}}},
    {"scan_progress_label", {{"tr","Taranıyor"},{"en","Scanning"}}},
    {"scan_unit",           {{"tr","dosya"},{"en","file"}}},
    {"scan_yara_loaded",    {{"tr","YARA kuralları yüklendi: {}"},{"en","YARA rules loaded: {}"}}},
    {"scan_starting",       {{"tr","Tarama başlatılıyor: {}"},{"en","Starting scan: {}"}}},
    {"scan_extensions",     {{"tr","Taranacak uzantılar: {}"},{"en","Target extensions: {}"}}},
    {"scan_done_title",     {{"tr","TARAMA TAMAMLANDI"},{"en","SCAN COMPLETED"}}},
    {"scan_total",          {{"tr","Toplam dosya"},{"en","Total files"}}},
    {"scan_scanned",        {{"tr","Taranan"},{"en","Scanned"}}},
    {"scan_cached",         {{"tr","Cache'den atlandı"},{"en","Skipped (cache)"}}},
    {"scan_yara_matches",   {{"tr","YARA eşleşmesi"},{"en","YARA matches"}}},
    {"scan_confirmed",      {{"tr","Onaylanan enfeksiyon"},{"en","Confirmed infection"}}},
    {"scan_false_pos",      {{"tr","Yanlış pozitif"},{"en","False positive"}}},
    {"scan_infection_confirmed", {{"tr","ENFEKSİYON ONAYLANDI"},{"en","INFECTION CONFIRMED"}}},

    // === Dosya Tarama Sonuçları ===
    {"title_scanning",      {{"tr","Luckyware Temizleyici - Taranıyor... {}"},{"en","Luckyware Cleaner - Scanning... {}"}}},
    {"title_idle",          {{"tr","Luckyware Temizleyici - Hazır"},{"en","Luckyware Cleaner - Ready"}}},
    {"title_counting",      {{"tr","Luckyware Temizleyici - Dosyalar sayılıyor..."},{"en","Luckyware Cleaner - Counting files..."}}},

    // === YARA ===
    {"rule_found",          {{"tr","Kural dosyası bulundu: {}"},{"en","Rules file found: {}"}}},
    {"rule_missing",        {{"tr","⚠ YARA kural dosyası bulunamadı! {}"},{"en","⚠ YARA rules file not found! {}"}}},

    // === Mutex ===
    {"mutex_title",         {{"tr","🔒 MUTEX / SÜREÇ TESPİTİ"},{"en","🔒 MUTEX / PROCESS DETECTION"}}},
    {"mutex_static",        {{"tr","Statik mutex kontrolü..."},{"en","Checking static mutexes..."}}},
    {"mutex_dynamic",       {{"tr","Dinamik mutex kontrolü..."},{"en","Checking dynamic mutexes..."}}},
    {"mutex_active",        {{"tr","AKTİF MUTEX BULUNDU: {}"},{"en","ACTIVE MUTEX FOUND: {}"}}},
    {"mutex_clean",         {{"tr","Mutex temiz ✓"},{"en","No suspicious mutex found ✓"}}},
    {"mutex_found_count",   {{"tr","{} şüpheli mutex/süreç tespit edildi!"},{"en","{} suspicious mutex/process detected!"}}},
    {"mutex_lw_running",    {{"tr","⚠ Luckyware payload aktif olabilir!"},{"en","⚠ Luckyware payload may be active!"}}},
    {"mutex_processes",     {{"tr","Zararlı süreç kontrolü..."},{"en","Checking for malicious processes..."}}},
    {"malicious_process",   {{"tr","ZARARLI SÜREÇ: {}"},{"en","MALICIOUS PROCESS: {}"}}},
    {"dropper_running",     {{"tr","Luckyware dropper çalışıyor!"},{"en","Luckyware dropper is running!"}}},

    // === Loader ===
    {"loader_title",        {{"tr","🔄 LOADER/STUB MUTEX TESPİTİ"},{"en","🔄 LOADER/STUB MUTEX DETECTION"}}},
    {"loader_checking",     {{"tr","Loader mutex'leri kontrol ediliyor..."},{"en","Checking loader mutexes..."}}},
    {"loader_clean",        {{"tr","Loader mutex/imzası bulunamadı ✓"},{"en","No loader mutex/signature found ✓"}}},
    {"loader_found",        {{"tr","{} Loader belirtisi!"},{"en","{} loader indicators!"}}},
    {"loader_sharedmem",    {{"tr","SHARED MEM İMZASI (0xBA73593C): PID={}"},{"en","SHARED MEM SIGNATURE (0xBA73593C): PID={}"}}},
    {"loader_running",      {{"tr","⚠ Luckyware Loader/Stub aktif olabilir!"},{"en","⚠ Luckyware Loader/Stub may be active!"}}},

    // === DNS Bypass ===
    {"dns_title",           {{"tr","🌐 DNS-over-HTTPS BYPASS TESPİTİ"},{"en","🌐 DNS-over-HTTPS BYPASS DETECTION"}}},
    {"dns_checking",        {{"tr","dns.google:443 bağlantıları kontrol ediliyor..."},{"en","Checking dns.google:443 connections..."}}},
    {"dns_found",           {{"tr","DoH BYPASS: PID={} ({}) → dns.google:443"},{"en","DoH BYPASS: PID={} ({}) → dns.google:443"}}},
    {"dns_clean",           {{"tr","Şüpheli DoH bağlantısı bulunamadı ✓"},{"en","No suspicious DoH connections found ✓"}}},
    {"dns_found_count",     {{"tr","{} DoH bypass tespit edildi!"},{"en","{} DoH bypass connections detected!"}}},

    // === Hollowing ===
    {"hollow_title",        {{"tr","🕳️ PROCESS HOLLOWING (Genişletilmiş)"},{"en","🕳️ PROCESS HOLLOWING (Extended)"}}},
    {"hollow_found",        {{"tr","{} hollowed process tespit edildi!"},{"en","{} hollowed processes detected!"}}},
    {"hollow_clean",        {{"tr","Tüm sistem süreçleri meşru ✓"},{"en","All system processes are legitimate ✓"}}},

    // === Kill ===
    {"kill_title",          {{"tr","🔪 ZARARLI SÜREÇ SONLANDIRMA"},{"en","🔪 MALICIOUS PROCESS TERMINATION"}}},
    {"kill_success",        {{"tr","SONLANDIRILDI: PID={} ({})"},{"en","TERMINATED: PID={} ({})"}}},
    {"kill_fail",           {{"tr","Sonlandırılamadı: PID={}"},{"en","Failed to terminate: PID={}"}}},
    {"kill_none",           {{"tr","Sonlandırılacak zararlı süreç bulunamadı."},{"en","No malicious processes to terminate."}}},
    {"kill_count",          {{"tr","{} süreç sonlandırıldı."},{"en","{} processes terminated."}}},

    // === Registry ===
    {"registry_title",      {{"tr","🗂️ REGISTRY TARAMASI"},{"en","🗂️ REGISTRY SCAN"}}},
    {"registry_checking",   {{"tr","Run/RunOnce kayıtları kontrol ediliyor..."},{"en","Checking Run/RunOnce entries..."}}},
    {"registry_found",      {{"tr","⚠ ZARARLI KAYIT: {} = {}"},{"en","⚠ MALICIOUS ENTRY: {} = {}"}}},
    {"registry_deleted",    {{"tr","Silindi: {}"},{"en","Deleted: {}"}}},
    {"registry_clean",      {{"tr","Registry temiz ✓"},{"en","Registry is clean ✓"}}},

    // === SDK ===
    {"sdk_title",           {{"tr","🔧 WINDOWS SDK / windows.h TARAMASI"},{"en","🔧 WINDOWS SDK / windows.h SCAN"}}},
    {"sdk_clean",           {{"tr","SDK dosyaları temiz ✓"},{"en","SDK files are clean ✓"}}},
    {"sdk_infected",        {{"tr","ENFEKTELİ SDK: {}"},{"en","INFECTED SDK: {}"}}},
    {"sdk_cleaned",         {{"tr","VccLibaries kaldırıldı: {}"},{"en","VccLibaries removed: {}"}}},

    // === ImGui ===
    {"imgui_title",         {{"tr","🎮 IMGUI KAYNAK KOD TARAMASI"},{"en","🎮 IMGUI SOURCE CODE SCAN"}}},
    {"imgui_clean",         {{"tr","ImGui dosyaları temiz ✓"},{"en","ImGui files are clean ✓"}}},
    {"imgui_infected",      {{"tr","ENFEKTELİ: {}"},{"en","INFECTED: {}"}}},
    {"imgui_cleaned",       {{"tr","Hex payload kaldırıldı: {}"},{"en","Hex payload removed: {}"}}},

    // === ProgramData ===
    {"pd_title",            {{"tr","📁 PROGRAMDATA ARTIFACT TARAMASI"},{"en","📁 PROGRAMDATA ARTIFACT SCAN"}}},
    {"pd_clean",            {{"tr","ProgramData temiz ✓"},{"en","ProgramData is clean ✓"}}},

    // === HOSTS ===
    {"hosts_title",         {{"tr","🌍 HOSTS DOSYASI"},{"en","🌍 HOSTS FILE"}}},
    {"hosts_block_done",    {{"tr","{} domain engellendi."},{"en","{} domains blocked."}}},
    {"hosts_restore_done",  {{"tr","{} engel satırı kaldırıldı."},{"en","{} block entries removed."}}},
    {"hosts_clean",         {{"tr","HOSTS zaten temiz ✓"},{"en","HOSTS file is already clean ✓"}}},

    // === Genel Özet ===
    {"results_title",       {{"tr","📊 GENEL TARAMA ÖZETİ"},{"en","📊 OVERALL SCAN SUMMARY"}}},
    {"results_infected",    {{"tr","Enfekte dosya"},{"en","Infected files"}}},
    {"results_mutex",       {{"tr","Mutex/Süreç"},{"en","Mutex/Process"}}},
    {"results_sdk",         {{"tr","SDK enfeksiyonu"},{"en","SDK infection"}}},
    {"results_imgui",       {{"tr","ImGui enfeksiyonu"},{"en","ImGui infection"}}},
    {"results_c2",          {{"tr","GitHub C2 domain"},{"en","GitHub C2 domain"}}},
    {"results_active_rat",  {{"tr","⚠ RAT AKTİF"},{"en","⚠ RAT ACTIVE"}}},

    // === Interaktif Temizleme ===
    {"ask_clean_interactive", {{"tr","Tespit edilen zararlıları otomatik temizlemek ister misiniz? (e/h): "},{"en","Would you like to automatically clean detected threats? (y/n): "}}},
    {"file_deleted_interactive", {{"tr","Silindi: "},{"en","Deleted: "}}},
    {"clean_success_interactive", {{"tr","✓ SİSTEM BAŞARIYLA TEMİZLENDİ!"},{"en","✓ SYSTEM SUCCESSFULLY CLEANED!"}}},

    // === VCXPROJ / SUO ===
    {"vcxproj_cleaned",     {{"tr","VCXPROJ temizlendi: {}"},{"en","VCXPROJ cleaned: {}"}}},
    {"suo_deleted",         {{"tr","SUO silindi: {}"},{"en","SUO deleted: {}"}}},

    // === C2 Blocking ===
    {"blocking_c2",         {{"tr","C2 domainleri HOSTS'a engelleniyor..."},{"en","Blocking C2 domains in HOSTS..."}}},
};

// -----------------------------------------------------------
// t() helper - format string replacement ({} placeholders)
// -----------------------------------------------------------
template<typename... Args>
inline std::string t(const std::string& key, Args&&... args) {
    auto it = TEXTS.find(key);
    std::string result;
    if (it != TEXTS.end()) {
        auto lang_it = it->second.find(LANG);
        if (lang_it != it->second.end())
            result = lang_it->second;
        else {
            auto en = it->second.find("en");
            result = (en != it->second.end()) ? en->second : key;
        }
    } else {
        result = key;
    }
    // Replace {} placeholders with args
    std::vector<std::string> argVec;
    (argVec.push_back([](auto&& a) {
        std::ostringstream oss; oss << a; return oss.str();
    }(std::forward<Args>(args))), ...);
    for (auto& arg : argVec) {
        auto pos = result.find("{}");
        if (pos != std::string::npos)
            result.replace(pos, 2, arg);
    }
    return result;
}

inline void set_lang(const std::string& l) {
    LANG = (l == "en" || l == "EN" || l == "2") ? "en" : "tr";
}

} // namespace Lang
