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
    {"scan_path_not_found", {{"tr","Tarama yolu bulunamadı: "},{"en","Scan path not found: "}}},
    {"best_clean_command",  {{"tr","En iyi temizleme komutu:"},{"en","Best cleaning command:"}}},
    {"options_title",       {{"tr","Seçenekler:"},{"en","Options:"}}},
    {"opt_block",           {{"tr","C2 domainlerini HOSTS'a engelle"},{"en","Block C2 domains in HOSTS"}}},
    {"opt_remove",          {{"tr","Enfekte dosyaları otomatik temizle"},{"en","Automatically clean infected files"}}},
    {"opt_patch_pe",        {{"tr","Zararlı PE bölümlerini patch'le"},{"en","Patch malicious PE sections"}}},
    {"opt_kill_process",    {{"tr","Zararlı süreçleri sonlandır"},{"en","Terminate malicious processes"}}},
    {"opt_unblock",         {{"tr","HOSTS'tan Luckyware engellerini kaldır"},{"en","Remove Luckyware blocks from HOSTS"}}},
    {"opt_clean_registry",  {{"tr","Registry'den zararlı Run kayıtlarını sil"},{"en","Delete malicious Run keys from Registry"}}},
    {"opt_clean_sdk",       {{"tr","windows.h'dan VccLibaries'i kaldır"},{"en","Remove VccLibaries from windows.h"}}},
    {"opt_clean_imgui",     {{"tr","imgui_impl_win32.cpp'den hex payload'ı kaldır"},{"en","Remove hex payload from imgui_impl_win32.cpp"}}},
    {"opt_clean_discord",   {{"tr","Discord enjeksiyonlarını temizle"},{"en","Clean Discord injections"}}},
    {"opt_full_clean",      {{"tr","Tüm temizleme modüllerini çalıştır"},{"en","Run all cleaning modules"}}},
    {"opt_rules",           {{"tr","YARA kural dosyası (varsayılan: rules\\luckyware.yar)"},{"en","YARA rules file (default: rules\\luckyware.yar)"}}},
    {"opt_lang",            {{"tr","Dil seçimi"},{"en","Language selection"}}},
    {"opt_clear_cache",     {{"tr","SHA256 cache'i temizle"},{"en","Clear SHA256 cache"}}},
    {"opt_debug",           {{"tr","Hata ayıklama modu"},{"en","Debug mode"}}},

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
    {"infected_registry",   {{"tr","⚠ {} zararlı registry kaydı bulundu!"},{"en","⚠ {} malicious registry keys found!"}}},
    {"c2_active_warning",   {{"tr","AKTİF C2 DOMAIN: {} domain engellenmemiş!"},{"en","ACTIVE C2 DOMAIN: {} domain(s) not blocked!"}}},
    {"c2_blocked_success",  {{"tr","C2 domainleri engelli ✓"},{"en","C2 domains are blocked ✓"}}},
    {"affected_programs",   {{"tr","Etkilenen programlar: "},{"en","Affected programs: "}}},
    {"reinstall_prompt",    {{"tr","Winget ile yeniden kurulum yapılsın mı? (e/h): "},{"en","Reinstall with Winget? (y/n): "}}},
    {"reinstalling",        {{"tr","Yeniden kuruluyor: "},{"en","Reinstalling: "}}},
    {"threats_found",       {{"tr","{} tehdit tespit edildi!"},{"en","{} threats detected!"}}},
    {"system_clean_toast",  {{"tr","Sistem temiz - Tehdit bulunamadi!"},{"en","System clean - No threats found!"}}},
    {"clean_completed",     {{"tr","Temizleme tamamlandi!"},{"en","Cleaning completed!"}}},
    {"clean_temp_prompt",   {{"tr","Tehdit bulunamadı. %TEMP% klasörlerini gene de temizlemek ister misiniz? (e/h): "},{"en","No threats found. Would you still like to clean %TEMP% folders? (y/n): "}}},
    {"critical_cpp_error",  {{"tr","[!] KRITIK C++ HATASI (CRASH ONLENDI): "},{"en","[!] CRITICAL C++ ERROR (CRASH PREVENTED): "}}},
    {"unknown_error",       {{"tr","[!] BILINMEYEN BIR HATA OLUSTU!"},{"en","[!] AN UNKNOWN ERROR OCCURRED!"}}},

    // === Interaktif Temizleme ===
    {"ask_clean_interactive", {{"tr","Tespit edilen zararlıları otomatik temizlemek ister misiniz? (e/h): "},{"en","Would you like to automatically clean detected threats? (y/n): "}}},
    {"file_deleted_interactive", {{"tr","Silindi: "},{"en","Deleted: "}}},
    {"clean_success_interactive", {{"tr","✓ SİSTEM BAŞARIYLA TEMİZLENDİ!"},{"en","✓ SYSTEM SUCCESSFULLY CLEANED!"}}},

    // === VCXPROJ / SUO ===
    {"vcxproj_cleaned",     {{"tr","VCXPROJ temizlendi: {}"},{"en","VCXPROJ cleaned: {}"}}},
    {"suo_deleted",         {{"tr","SUO silindi: {}"},{"en","SUO deleted: {}"}}},

    // === C2 Blocking ===
    {"blocking_c2",         {{"tr","C2 domainleri HOSTS'a engelleniyor..."},{"en","Blocking C2 domains in HOSTS..."}}},
    
    // === Internet Control & Advanced Scanning ===
    {"ask_disconnect_network", {{"tr","  \u26a0 Tarama sirasinda interneti kesmek ister misiniz? [E/H]: "},{"en","  \u26a0 Would you like to disconnect internet during scan? [Y/N]: "}}},
    {"network_disconnecting", {{"tr","  \u26a0 Internet baglantisi kesiliyor..."},{"en","  \u26a0 Disconnecting internet connection..."}}},
    {"network_restoring",   {{"tr","  \u2705 Internet baglantisi geri getiriliyor..."},{"en","  \u2705 Restoring internet connection..."}}},
    {"network_disconnected", {{"tr","  \u2705 Internet baglantisi kesildi."},{"en","  \u2705 Internet connection disconnected."}}},
    {"network_restored",    {{"tr","  \u2705 Internet baglantisi geri getirildi."},{"en","  \u2705 Internet connection restored."}}},
    {"sys_integrity_title", {{"tr","[Sistem Butunluk Kontrolu]"},{"en","[System Integrity Check]"}}},
    {"checking_cldapi",     {{"tr","  \u23f3 cldapi.dll kontrol ediliyor..."},{"en","  \u23f3 Checking cldapi.dll..."}}},
    {"cldapi_clean",        {{"tr","  \u2705 cldapi.dll temiz gorunuyor."},{"en","  \u2705 cldapi.dll looks clean."}}},
    {"cldapi_infected",     {{"tr","  \u26a0 cldapi.dll ENFEKTE! (Zararli pe-load saptandi)"},{"en","  \u26a0 cldapi.dll INFECTED! (Malicious pe-load detected)"}}},
    {"prebuild_injection_short", {{"tr","MSBuild <PreBuildEvent> Enjeksiyonu"},{"en","MSBuild <PreBuildEvent> Injection"}}},

    // === Scanner Output ===
    {"cache_cleared",       {{"tr","Cache temizlendi."},{"en","Cache cleared."}}},
    {"scan_cache_empty",    {{"tr","Cache boş/bulunamadı."},{"en","Cache empty/not found."}}},
    {"scan_cache_loaded",   {{"tr","Cache yüklendi: {} kayıt"},{"en","Cache loaded: {} entries"}}},
    {"prebuild_injection",  {{"tr","PreBuildEvent zararlı kod enjeksiyonu tespit edildi"},{"en","PreBuildEvent malicious code injection detected"}}},
    {"suspicious_file",     {{"tr","Şüpheli dosya içeriği tespit edildi"},{"en","Suspicious file content detected"}}},
    {"suspicious_structure",{{"tr","Şüpheli Yapı Tespit Edildi: {}"},{"en","Suspicious Structure Detected: {}"}}},
    {"match_found",          {{"tr","Eşleşen dize"},{"en","Matched string"}}},
    // === Detector Output ===
    {"static_mutex",        {{"tr","Genel Mutex"},{"en","Global Mutex"}}},
    {"infdll_mutex",        {{"tr","InfDLL dinamik mutex (TheDLL.cpp:117)"},{"en","InfDLL dynamic mutex (TheDLL.cpp:117)"}}},
    {"dynamic_mutex_found", {{"tr","DİNAMİK MUTEX BULUNDU: {}"},{"en","DYNAMIC MUTEX FOUND: {}"}}},
    {"loader_pfnmx",        {{"tr","LOADER MUTEX BULUNDU: {}"},{"en","LOADER MUTEX FOUND: {}"}}},
    {"drop_process",        {{"tr","INFDLL DROPPER SÜRECİ: {}"},{"en","INFDLL DROPPER PROCESS: {}"}}},
    {"sdk_drop_proc",       {{"tr","SDK INFECTOR DROPPER: {}"},{"en","SDK INFECTOR DROPPER: {}"}}},
    {"imgui_drop_proc",     {{"tr","IMGUI INFECTOR DROPPER: {}"},{"en","IMGUI INFECTOR DROPPER: {}"}}},
    {"check_proc",          {{"tr","Kontrol: "},{"en","Checking: "}}},
    {"single_thread_proc",  {{"tr","Tek thread (\u2264 1) \u2014 CREATE_SUSPENDED belirtisi"},{"en","Single thread (\u2264 1) \u2014 CREATE_SUSPENDED indicator"}}},
    {"fake_path",           {{"tr","Sahte yol: {}"},{"en","Fake path: {}"}}},
    {"path_unreadable",     {{"tr","Yol okunamadı (erişim engeli \u2014 hollowing?)"},{"en","Path unreadable (access denied \u2014 hollowing?)"}}},
    {"hollow_proc",         {{"tr","HOLLOW: {} PID={}"},{"en","HOLLOW: {} PID={}"}}},
    {"dns_active_doh",      {{"tr","Aktif DoH HTTPS bağlantısı tespit edildi!"},{"en","Active DoH HTTPS connection detected!"}}},
    {"dns_target",          {{"tr","Hedef: {}:443"},{"en","Target: {}:443"}}},
    {"dns_bypass_active",   {{"tr","Aktif DoH HTTPS bağlantısı tespit edildi!"},{"en","Active DoH HTTPS connection detected!"}}},
    {"c2_github_check",     {{"tr","GitHub C2 domain kontrolü (HOSTS engel durumu)..."},{"en","GitHub C2 domain check (HOSTS block status)..."}}},
    {"c2_not_blocked",      {{"tr","ENGELLENMEMİŞ C2 DOMAIN: {} → {}"},{"en","UNBLOCKED C2 DOMAIN: {} → {}"}}},
    {"hosts_read_err",      {{"tr","HOSTS dosyası okunamadı!"},{"en","Failed to read HOSTS file!"}}},
    {"hosts_write_err",     {{"tr","HOSTS dosyasına yazılamadı! Yönetici yetkisi gerekli."},{"en","Failed to write to HOSTS file! Administrator privileges required."}}},
    {"hosts_blocked",       {{"tr","Engellendi: {}"},{"en","Blocked: {}"}}},
    
    // === Cleaner Output ===
    {"prebuild_deleted",    {{"tr","<PreBuildEvent> bloğu komple silindi: {}"},{"en","<PreBuildEvent> block completely deleted: {}"}}},
    {"suo_del_err",         {{"tr","SUO silinemedi: {}"},{"en","Failed to delete SUO: {}"}}},
    {"sdk_infection_found", {{"tr","Enfeksiyon bulundu: {}"},{"en","Infection found: {}"}}},
    {"sdk_file_fixed",      {{"tr","SDK dosyası düzeltildi: {}"},{"en","SDK file fixed: {}"}}},
    {"temp_clean_title",    {{"tr","TEMP KLASÖRÜ TEMİZLİĞİ"},{"en","TEMP FOLDER CLEANUP"}}},
    {"temp_cleaning",       {{"tr","Geçici dosyalar (%TEMP% ve %TMP%) temizleniyor..."},{"en","Cleaning temporary files (%TEMP% and %TMP%)..."}}},
    {"temp_files_deleted",  {{"tr","{} geçici dosya/klasör kalıcı olarak silindi."},{"en","{} temporary files/folders permanently deleted."}}},
    {"temp_already_clean",  {{"tr","Temp klasörleri zaten temizdi."},{"en","Temp folders were already clean."}}},
    {"temp_files_skipped",  {{"tr","{} dosya kilitli olduğu için atlandi (reboot sonrası silinebilir)."},{"en","{} files skipped because they are locked (might be deleted after reboot)."}}},
    {"hosts_blocking_c2",   {{"tr","C2 domainleri HOSTS dosyasina engelleniyor..."},{"en","Blocking C2 domains in HOSTS file..."}}},
    {"hosts_added_c2",      {{"tr","HOSTS engeli eklendi: {}"},{"en","HOSTS block added: {}"}}},
    {"hosts_blocked_new",   {{"tr","{} yeni C2 domaini engellendi."},{"en","{} new C2 domains blocked."}}},
    {"hosts_all_safe",      {{"tr","Engellenmesi gereken yeni domain yok, hepsi guvende."},{"en","No new domains to block, all safe."}}},
    {"winget_running",      {{"tr","Çalıştırılıyor: {}"},{"en","Running: {}"}}},
    {"proc_killed_pid",     {{"tr","Süreç sonlandırıldı: {} (PID: {})"},{"en","Process terminated: {} (PID: {})"}}},
    {"malware_scan_title",  {{"tr","ZARARLI SÜREÇ TARAMASİ"},{"en","MALICIOUS PROCESS SCAN"}}},
    {"malware_scanning",    {{"tr","Bilinen zararlı süreçler taranıyor ve sonlandırılıyor..."},{"en","Scanning and terminating known malicious processes..."}}},
    {"malware_killed",      {{"tr","{} zararlı/enjekte süreç sonlandırıldı."},{"en","{} malicious/injected processes terminated."}}},
    {"malware_not_found",   {{"tr","Aktif zararlı süreç bulunamadı."},{"en","No active malicious processes found."}}},
    {"payload_clean_title", {{"tr","ZARARLI DOSYA TEMİZLİĞİ"},{"en","MALICIOUS FILE CLEANUP"}}},
    {"payload_cleaning",    {{"tr","Bilinen zararlı payload dosyaları temizleniyor..."},{"en","Cleaning known malicious payload files..."}}},
    {"payload_deleted",     {{"tr","{} zararlı dosya/klasör silindi."},{"en","{} malicious files/folders deleted."}}},
    {"payload_not_found",   {{"tr","Bilinen zararlı dosya bulunamadı."},{"en","No known malicious files found."}}},
    {"discord_clean_title", {{"tr","DISCORD TEMİZLİĞİ"},{"en","DISCORD CLEANUP"}}},
    {"discord_cleaning",    {{"tr","Discord enjeksiyon temizliği başlatılıyor..."},{"en","Starting Discord injection cleanup..."}}},
    {"discord_closing",     {{"tr","Discord süreçleri kapatılıyor..."},{"en","Closing Discord processes..."}}},
    {"discord_no_localapp", {{"tr","LOCALAPPDATA okunamadı."},{"en","LOCALAPPDATA unreadable."}}},
    {"discord_dll_del",     {{"tr","Enjekte DLL silindi: {}"},{"en","Injected DLL deleted: {}"}}},
    {"discord_dll_err",     {{"tr","Silinemedi (kilitli?): {}"},{"en","Failed to delete (locked?): {}"}}},
    {"discord_js_del",      {{"tr","Zararlı JS silindi: {}"},{"en","Malicious JS deleted: {}"}}},
    {"discord_clean_done",  {{"tr","{} Discord enjeksiyonu temizlendi."},{"en","{} Discord injections cleaned."}}},
    {"discord_already_clean",{{"tr","Discord temiz, enjeksiyon bulunamadı."},{"en","Discord clean, no injections found."}}},
    {"edge_clean_title",    {{"tr","EDGE HIJACK TEMİZLİĞİ"},{"en","EDGE HIJACK CLEANUP"}}},
    {"edge_cleaning",       {{"tr","Edge tarayıcı hijack dosyaları kontrol ediliyor..."},{"en","Checking Edge browser hijack files..."}}},
    {"edge_no_data",        {{"tr","Edge veri klasörü bulunamadı, atlanıyor."},{"en","Edge data folder not found, skipping."}}},
    {"edge_hijack_del",     {{"tr","Edge hijack klasörü silindi: {}"},{"en","Edge hijack folder deleted: {}"}}},
    {"edge_hijack_err",     {{"tr","Silinemedi: {}"},{"en","Failed to delete: {}"}}},
    {"edge_clean_done",     {{"tr","{} Edge hijack klasörü temizlendi."},{"en","{} Edge hijack folders cleaned."}}},
    {"edge_already_clean",  {{"tr","Edge temiz, hijack bulunamadı."},{"en","Edge clean, no hijacks found."}}},
    {"full_clean_title",    {{"tr","TAM TEMİZLİK MODU"},{"en","FULL CLEANUP MODE"}}},
    {"full_clean_starting", {{"tr","Tüm temizleme modülleri sırasıyla çalıştırılıyor...\n"},{"en","Running all cleanup modules sequentially...\n"}}},
    {"full_clean_done",     {{"tr","═══ TAM TEMİZLİK TAMAMLANDI ═══"},{"en","═══ FULL CLEANUP COMPLETED ═══"}}},
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
