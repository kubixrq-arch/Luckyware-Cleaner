#pragma once
// Luckyware Cleaner - PE Analysis
// Detects injected .rcd sections, embedded PE-in-PE, and the Luckyware XOR key.
#include <string>
#include <vector>
#include <fstream>
#include <cstring>
#include <algorithm>
#include <windows.h>

namespace PECheck {

struct SectionInfo {
    std::string name;
    DWORD characteristics;
    DWORD virtual_size;
    DWORD raw_size;
    DWORD raw_offset;
};

inline std::vector<SectionInfo> get_sections(const std::string& filepath) {
    std::vector<SectionInfo> sections;
    std::ifstream f(filepath, std::ios::binary);
    if (!f.is_open()) return sections;

    IMAGE_DOS_HEADER dos_hdr{};
    f.read(reinterpret_cast<char*>(&dos_hdr), sizeof(dos_hdr));
    if (dos_hdr.e_magic != IMAGE_DOS_SIGNATURE) return sections;

    f.seekg(dos_hdr.e_lfanew, std::ios::beg);

    DWORD pe_sig = 0;
    f.read(reinterpret_cast<char*>(&pe_sig), 4);
    if (pe_sig != IMAGE_NT_SIGNATURE) return sections;

    IMAGE_FILE_HEADER file_hdr{};
    f.read(reinterpret_cast<char*>(&file_hdr), sizeof(file_hdr));

    f.seekg(file_hdr.SizeOfOptionalHeader, std::ios::cur);

    for (WORD i = 0; i < file_hdr.NumberOfSections; ++i) {
        IMAGE_SECTION_HEADER sec_hdr{};
        f.read(reinterpret_cast<char*>(&sec_hdr), sizeof(sec_hdr));

        SectionInfo si;
        // Section name field is 8 bytes and may not be null-terminated
        char name_buf[9] = {};
        std::memcpy(name_buf, sec_hdr.Name, 8);
        si.name = name_buf;
        si.characteristics = sec_hdr.Characteristics;
        si.virtual_size = sec_hdr.Misc.VirtualSize;
        si.raw_size = sec_hdr.SizeOfRawData;
        si.raw_offset = sec_hdr.PointerToRawData;
        sections.push_back(si);
    }
    return sections;
}

struct RcdResult {
    bool found;
    std::string reason;
    std::vector<std::string> section_names;
};

// Detection logic based on Luckyware's mainito.h:356 — malicious sections use the
// .rcd prefix and are marked executable. Also checks for embedded PE (multiple MZ
// headers) and the hardcoded XOR key "NtExploreProcess".
inline RcdResult check_rcd_sections(const std::string& filepath) {
    RcdResult result{false, "", {}};
    auto sections = get_sections(filepath);
    if (sections.empty()) return result;

    for (auto& sec : sections)
        result.section_names.push_back(sec.name);

    for (auto& sec : sections) {
        if (sec.name.size() >= 4 && sec.name.substr(0, 4) == ".rcd") {
            bool exec     = (sec.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
            bool write    = (sec.characteristics & IMAGE_SCN_MEM_WRITE)   != 0;
            bool has_code = (sec.characteristics & IMAGE_SCN_CNT_CODE)    != 0;
            if (exec || has_code) {
                result.found = true;
                result.reason = "Zararlı .rcd bölümü (executable): " + sec.name;
                if (write) result.reason += " [WRITE+EXEC - shellcode!]";
                return result;
            }
        }
    }

    std::ifstream f(filepath, std::ios::binary);
    if (!f.is_open()) return result;
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)),
                               std::istreambuf_iterator<char>());
    f.close();

    int mz_count = 0;
    for (size_t i = 0; i + 1 < data.size(); ++i) {
        if (data[i] == 'M' && data[i+1] == 'Z') ++mz_count;
    }
    if (mz_count > 1) {
        result.found = true;
        result.reason = "Gömülü PE tespiti: " + std::to_string(mz_count) + " MZ başlığı";
        return result;
    }

    const std::string xor_key = "NtExploreProcess";
    if (data.size() > xor_key.size()) {
        auto pos = std::search(data.begin(), data.end(),
                               xor_key.begin(), xor_key.end());
        if (pos != data.end()) {
            result.found = true;
            result.reason = "Luckyware XOR anahtarı tespit edildi: NtExploreProcess";
        }
    }

    return result;
}

// Clears the MEM_EXECUTE and CNT_CODE flags from all .rcd sections in-place.
// Opens the file for both reading and writing without truncation.
inline bool patch_pe_section(const std::string& filepath) {
    std::fstream f(filepath, std::ios::binary | std::ios::in | std::ios::out);
    if (!f.is_open()) return false;

    IMAGE_DOS_HEADER dos_hdr{};
    f.read(reinterpret_cast<char*>(&dos_hdr), sizeof(dos_hdr));
    if (dos_hdr.e_magic != IMAGE_DOS_SIGNATURE) return false;

    f.seekg(dos_hdr.e_lfanew, std::ios::beg);
    DWORD pe_sig = 0;
    f.read(reinterpret_cast<char*>(&pe_sig), 4);
    if (pe_sig != IMAGE_NT_SIGNATURE) return false;

    IMAGE_FILE_HEADER file_hdr{};
    f.read(reinterpret_cast<char*>(&file_hdr), sizeof(file_hdr));
    f.seekg(file_hdr.SizeOfOptionalHeader, std::ios::cur);

    std::streampos section_start = f.tellg();
    bool patched = false;

    for (WORD i = 0; i < file_hdr.NumberOfSections; ++i) {
        std::streampos sec_pos = section_start + std::streampos(i * sizeof(IMAGE_SECTION_HEADER));
        f.seekg(sec_pos);

        IMAGE_SECTION_HEADER sec_hdr{};
        f.read(reinterpret_cast<char*>(&sec_hdr), sizeof(sec_hdr));

        char name_buf[9] = {};
        std::memcpy(name_buf, sec_hdr.Name, 8);
        std::string name = name_buf;

        if (name.size() >= 4 && name.substr(0, 4) == ".rcd") {
            if (sec_hdr.Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                sec_hdr.Characteristics &= ~IMAGE_SCN_MEM_EXECUTE;
                sec_hdr.Characteristics &= ~IMAGE_SCN_CNT_CODE;
                f.seekp(sec_pos);
                f.write(reinterpret_cast<char*>(&sec_hdr), sizeof(sec_hdr));
                patched = true;
            }
        }
    }
    return patched;
}

} // namespace PECheck
