#pragma once
// Luckyware Cleaner - String Obfuscation Module
// Prevents false-positive YARA detections on the cleaner's own binary.
// All sensitive string literals (C2 domains, malware indicators, regex fragments)
// are stored XOR-encoded and decoded at runtime so they never appear as
// contiguous plaintext in the compiled PE.
#include <string>
#include <vector>
#include <cstdint>

namespace Obf {

constexpr uint8_t KEY = 0x5A;

// Decode a XOR-encoded byte sequence back to a std::string.
inline std::string d(const uint8_t* data, size_t len) {
    std::string r(len, '\0');
    for (size_t i = 0; i < len; ++i)
        r[i] = static_cast<char>(data[i] ^ KEY);
    return r;
}

// ════════════════════════════════════════════════════════════════════════
// Helper macro: OBF(varname, "plaintext") expands to a static-local
// decoded string that is computed exactly once (thread-safe in C++11+).
// The XOR'd bytes are stored in a constexpr array; no plaintext in .rdata.
// ════════════════════════════════════════════════════════════════════════

// Internal: XOR every byte at compile time via a constexpr helper.
template <size_t N>
struct Enc {
    uint8_t data[N]{};
    constexpr Enc(const char (&s)[N]) {
        for (size_t i = 0; i < N; ++i)
            data[i] = static_cast<uint8_t>(s[i]) ^ KEY;
    }
};

// ════════════════════════════════════════════════════════════════════════
// C2 DOMAIN LIST (decoded on first call, cached)
// ════════════════════════════════════════════════════════════════════════
inline std::vector<std::string> c2_domains() {
    // Each domain is stored as Enc<> constexpr — the plaintext never
    // appears in the binary's string table.
    static constexpr Enc d01("pubshierstext.top");
    static constexpr Enc d02("frozi.cc");
    static constexpr Enc d03("concodro.lat");
    static constexpr Enc d04("krispykreme.top");
    static constexpr Enc d05("wallmart.mom");
    static constexpr Enc d06("stratum.ravenminer.com");
    static constexpr Enc d07("matchashop.icu");
    static constexpr Enc d08("vcc-library.online");
    static constexpr Enc d09("vcc-library.help");
    static constexpr Enc d10("i-slept-with-ur.mom");
    static constexpr Enc d11("i-like.boats");
    static constexpr Enc d12("devruntime.cy");
    static constexpr Enc d13("zetolacs-cloud.top");
    static constexpr Enc d14("exo-api.tf");
    static constexpr Enc d15("nuzzyservices.com");
    static constexpr Enc d16("darkside.cy");
    static constexpr Enc d17("balista.lol");
    static constexpr Enc d18("phobos.top");
    static constexpr Enc d19("phobosransom.com");
    static constexpr Enc d20("pee-files.nl");
    static constexpr Enc d21("vcc-library.uk");
    static constexpr Enc d22("luckyware.co");
    static constexpr Enc d23("luckyware.cc");
    static constexpr Enc d24("91.92.243.218");
    static constexpr Enc d25("dhszo.darkside.cy");
    static constexpr Enc d26("188.114.96.11");
    static constexpr Enc d27("risesmp.net");
    static constexpr Enc d28("luckystrike.pw");
    static constexpr Enc d29("vcc-redistrbutable.help");
    static constexpr Enc d30("bounty-valorant.lol");
    static constexpr Enc d31("textpubshiers.top");
    static constexpr Enc d32("balistat.lol");
    static constexpr Enc d33("contorosa.space");

    static std::vector<std::string> v;
    if (v.empty()) {
        auto D = [](const auto& e) { return d(e.data, sizeof(e.data) - 1); };
        v = { D(d01),D(d02),D(d03),D(d04),D(d05),D(d06),D(d07),D(d08),D(d09),D(d10),
              D(d11),D(d12),D(d13),D(d14),D(d15),D(d16),D(d17),D(d18),D(d19),D(d20),
              D(d21),D(d22),D(d23),D(d24),D(d25),D(d26),D(d27),D(d28),D(d29),
              D(d30),D(d31),D(d32),D(d33) };
    }
    return v;
}

// ════════════════════════════════════════════════════════════════════════
// REGISTRY REGEX PATTERN (built at runtime from obfuscated parts)
// Original: "(i-like\\.boats|krispykreme\\.top|nuzzyservices|devruntime\\.cy
//            |luckyware\\.co|bounty-valorant\\.lol|vcc-redistrbutable
//            |powershell.*windowstyle.*hidden
//            |iwr\\s+-uri.*berok
//            |berok\\.exe|zetolac\\.exe
//            |VccFramework|PFLwrx|CDat\\.bin)"
// ════════════════════════════════════════════════════════════════════════
inline std::string registry_regex_pattern() {
    static constexpr Enc p01("i-like\\.boats");
    static constexpr Enc p02("krispykreme\\.top");
    static constexpr Enc p03("nuzzyservices");
    static constexpr Enc p04("devruntime\\.cy");
    static constexpr Enc p05("luckyware\\.co");
    static constexpr Enc p06("bounty-valorant\\.lol");
    static constexpr Enc p07("vcc-redistrbutable");
    static constexpr Enc p08("powershell.*windowstyle.*hidden");
    static constexpr Enc p09("iwr\\s+-uri.*berok");
    static constexpr Enc p10("berok\\.exe");
    static constexpr Enc p11("zetolac\\.exe");
    static constexpr Enc p12("VccFramework");
    static constexpr Enc p13("PFLwrx");
    static constexpr Enc p14("CDat\\.bin");

    auto D = [](const auto& e) { return d(e.data, sizeof(e.data) - 1); };
    return "(" + D(p01) + "|" + D(p02) + "|" + D(p03) + "|" + D(p04)
         + "|" + D(p05) + "|" + D(p06) + "|" + D(p07)
         + "|" + D(p08)
         + "|" + D(p09)
         + "|" + D(p10) + "|" + D(p11)
         + "|" + D(p12) + "|" + D(p13) + "|" + D(p14) + ")";
}

// ════════════════════════════════════════════════════════════════════════
// MALWARE PROCESS NAMES (for kill_malware_processes)
// ════════════════════════════════════════════════════════════════════════
inline std::vector<std::string> malware_process_names() {
    static constexpr Enc n01("Berok.exe");
    static constexpr Enc n02("HPSR.exe");
    static constexpr Enc n03("Zetolac.exe");
    static constexpr Enc n04("PedoClown666.jpeg");
    static constexpr Enc n05("TwerkMaster69.jpeg");
    static constexpr Enc n06("berok64.exe");
    static constexpr Enc n07("hpsr64.exe");

    auto D = [](const auto& e) { return d(e.data, sizeof(e.data) - 1); };
    return { D(n01), D(n02), D(n03), D(n04), D(n05), D(n06), D(n07) };
}

// ════════════════════════════════════════════════════════════════════════
// KNOWN MALICIOUS PROCESS NAMES (for mutex_scan)
// ════════════════════════════════════════════════════════════════════════
inline std::vector<std::string> known_malicious_names() {
    static constexpr Enc m01("berok.exe");
    static constexpr Enc m02("zetolac.exe");
    static constexpr Enc m03("hpsr.exe");
    static constexpr Enc m04("msmodule.exe");
    static constexpr Enc m05("berok64.exe");
    auto D = [](const auto& e) { return d(e.data, sizeof(e.data) - 1); };
    return { D(m01), D(m02), D(m03), D(m04), D(m05) };
}

// ════════════════════════════════════════════════════════════════════════
// DROPPED FILE NAMES
// ════════════════════════════════════════════════════════════════════════
inline std::vector<std::string> appdata_drops() {
    static constexpr Enc f01("Berok.exe");
    static constexpr Enc f02("HPSR.exe");
    static constexpr Enc f03("Zetolac.exe");
    auto D = [](const auto& e) { return d(e.data, sizeof(e.data) - 1); };
    return { D(f01), D(f02), D(f03) };
}

inline std::vector<std::string> vbs_drops() {
    static constexpr Enc f01("reg.vbs");
    static constexpr Enc f02("disk.vbs");
    static constexpr Enc f03("SyncAppvPublishingServer.vbs"); // Only if in unauthorized folder
    auto D = [](const auto& e) { return d(e.data, sizeof(e.data) - 1); };
    return { D(f01), D(f02), D(f03) };
}

// ════════════════════════════════════════════════════════════════════════
// INFECTION MARKERS (for find() checks in Discord/ImGui/SDK cleaners)
// ════════════════════════════════════════════════════════════════════════
inline std::string marker_vcclib()    { static constexpr Enc e("VccLibaries");    return d(e.data, sizeof(e.data)-1); }
inline std::string marker_vcclib2()   { static constexpr Enc e("VCCLibraries_");  return d(e.data, sizeof(e.data)-1); }
inline std::string marker_wfkuuv()    { static constexpr Enc e("wfkuuv157wg2gjthwla0lwbo1493h7"); return d(e.data, sizeof(e.data)-1); }
inline std::string marker_systemf()   { static constexpr Enc e("system(F");       return d(e.data, sizeof(e.data)-1); }
inline std::string marker_luckyware() { static constexpr Enc e("luckyware");      return d(e.data, sizeof(e.data)-1); }
inline std::string marker_domdoc()    { static constexpr Enc e("MSXml2.DOMDocument"); return d(e.data, sizeof(e.data)-1); }
inline std::string marker_adodb()     { static constexpr Enc e("ADODB.Recordset"); return d(e.data, sizeof(e.data)-1); }

// ════════════════════════════════════════════════════════════════════════
// SCANNER PREBUILD DETECTION STRINGS (for vcxproj scanner in scanner.hpp)
// ════════════════════════════════════════════════════════════════════════
inline std::string scan_powershell()     { static constexpr Enc e("powershell");             return d(e.data, sizeof(e.data)-1); }
inline std::string scan_winstyle_hid()   { static constexpr Enc e("-windowstyle hidden");    return d(e.data, sizeof(e.data)-1); }
inline std::string scan_execpol_byp()    { static constexpr Enc e("-executionpolicy bypass");return d(e.data, sizeof(e.data)-1); }
inline std::string scan_iwr_uri()        { static constexpr Enc e("iwr -uri");               return d(e.data, sizeof(e.data)-1); }
inline std::string scan_invoke_wr()      { static constexpr Enc e("invoke-webrequest");      return d(e.data, sizeof(e.data)-1); }
inline std::string scan_start_proc()     { static constexpr Enc e("start-process");          return d(e.data, sizeof(e.data)-1); }
inline std::string scan_env_appdata()    { static constexpr Enc e("$env:appdata");            return d(e.data, sizeof(e.data)-1); }
inline std::string scan_wscript()        { static constexpr Enc e("wscript.shell");          return d(e.data, sizeof(e.data)-1); }
inline std::string scan_adodb()          { static constexpr Enc e("adodb.recordset");        return d(e.data, sizeof(e.data)-1); }
inline std::string scan_base64()         { static constexpr Enc e("bin.base64");             return d(e.data, sizeof(e.data)-1); }
inline std::string scan_berok()          { static constexpr Enc e("berok.exe");              return d(e.data, sizeof(e.data)-1); }
inline std::string scan_hpsr()           { static constexpr Enc e("hpsr.exe");               return d(e.data, sizeof(e.data)-1); }
inline std::string scan_zetolac()        { static constexpr Enc e("zetolac.exe");            return d(e.data, sizeof(e.data)-1); }
inline std::string scan_retev()          { static constexpr Enc e("retev.php");              return d(e.data, sizeof(e.data)-1); }
inline std::string scan_wfkuuv()         { static constexpr Enc e("wfkuuv157wg2gjthwla0lwbo1493h7"); return d(e.data, sizeof(e.data)-1); }

} // namespace Obf
