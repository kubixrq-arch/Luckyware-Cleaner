<div align="center">

# 🛡️ Luckyware Cleaner Tool

**YARA-powered malware scanner & automated cleaner for Luckyware infections**

**YARA tabanlı zararlı yazılım tarayıcı & otomatik temizleyici**

[![C++](https://img.shields.io/badge/C++-17-00599C?style=for-the-badge&logo=cplusplus&logoColor=white)](https://isocpp.org/)
[![Windows](https://img.shields.io/badge/Windows-10%2F11-0078D6?style=for-the-badge&logo=windows&logoColor=white)](https://www.microsoft.com/windows)
[![YARA](https://img.shields.io/badge/YARA-Rules-FF6F00?style=for-the-badge&logo=virustotal&logoColor=white)](https://virustotal.github.io/yara/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

---

</div>

---

[English](#-english) • [Türkçe](#-türkçe)

### ✨ Features / Özellikler

| Feature            | EN                            | TR                                      |
| ------------------ | ----------------------------- | --------------------------------------- |
| 🌐 Language         | English & Turkish support     | İngilizce & Türkçe desteği              |
| 🔍 YARA Scanner     | YARA-based malware detection  | YARA tabanlı zararlı tespit             |
| 🧹 Auto Cleaner     | Reg, SDK, ImGui, Discord, Temp| Reg, SDK, ImGui, Discord, Temp temizleme|
| 📡 Network Ctrl     | Internet kill-switch during scan| Tarama sırasında internet kesme        |
| 🛡️ Smart PE Scan    | Magic-byte based EXE detection| Magic-byte tabanlı EXE tespiti          |
| 🚫 C2 Block         | Permanently block C2 domains  | C2 domainlerini kalıcı olarak engelle   |
| ⚡ Optimized        | Dynamic multi-threading & Cache| Dinamik çoklu işleme & Önbellek        |
| 📋 Detailed Logs    | Shows matched malicious strings| Eşleşen zararlı dizeleri gösterir      |

---

## 🇬🇧 English

### 📋 System Requirements

| Requirement         | Details                               |
| ------------------- | ------------------------------------- |
| **Compiler**        | Visual Studio 2022 (MSVC v143, C++17) |
| **OS**              | Windows 10/11 (64-bit)                |
| **Privileges**      | Administrator (Run as Admin)          |
| **Package Manager** | winget (for reinstallation)           |

### 🔨 Building

Open `LuckywareCleaner.sln` in Visual Studio 2022 and build in **Release** mode. The YARA rules (`rules/luckyware.yar`) are automatically copied to the output directory.

### 🚀 Usage Guide

> [!IMPORTANT]
> You **must** run the program **as Administrator**.

```bash
LuckywareCleaner.exe C:\ --block --patch-pe --remove --full-clean
```

<details>
<summary>⭐ <b>Command-line Flags Explained</b></summary>

| Flag               | Description                                     |
| ------------------ | ----------------------------------------------- |
| `--block`          | Permanently blocks C2 domains in HOSTS file     |
| `--unblock`        | Removes Luckyware blocks from HOSTS file        |
| `--patch-pe`       | Disables execution bit of malicious PE sections |
| `--remove`         | Removes infected SUO/VCXPROJ/temp files         |
| `--kill-process`   | Terminates malicious processes                  |
| `--clean-registry` | Removes malicious Run/RunOnce entries           |
| `--clean-sdk`      | Removes VccLibaries from windows.h              |
| `--clean-imgui`    | Removes hex payloads from imgui_impl_win32.cpp  |
| `--clean-discord`  | Cleans Discord injections                       |
| `--clean-vcxproj`  | Cleans only .vcxproj file injections            |
| `--full-clean`     | Runs all cleaning modules                       |
| `--clear-cache`    | Clears the SHA256 cache                         |
| `--rules <file>`   | Specifies the YARA rules file path              |
| `--lang tr\|en`    | Language selection                              |
| `--network`        | Force internet disconnect during scan           |
| `--debug`          | Enable debug output                             |

</details>

<details>
<summary>📝 <b>More Examples</b></summary>

```bash
# Scan only (no modifications)
LuckywareCleaner.exe C:\

# Interactive mode (prompts for language & path)
LuckywareCleaner.exe

# Scan with all protections / Tüm korumalarla tam tarama
LuckywareCleaner.exe C:\ --block --patch-pe --remove --full-clean
```

</details>

> [!NOTE]
> In interactive mode (no arguments), the program will guide you through language selection, path input, and offer to clean detected threats with your confirmation.

### ⚡ Quick Start

```bash
# 1. Build the project in Visual Studio (Release mode)
# 2. Open Command Prompt AS ADMINISTRATOR
# 3. Navigate to the output directory
cd "Luckyware Cleaner Tool\bin\Release"

# 4. Run full scan with all protections
LuckywareCleaner.exe C:\ --block --patch-pe --remove --full-clean

# 5. Follow the on-screen prompts
# 6. Restart your computer ✓
```

### ⚠️ Important Warnings

> [!WARNING]
> - Run the program **as Administrator**
> - Scanning the C: drive may take a **long time**
> - An additional scan with **Bitdefender Ultimate** is recommended
> - **Change ALL your passwords** after the process is complete

---

## 🇹🇷 Türkçe

### 📋 Sistem Gereksinimleri

| Gereksinim           | Detay                                 |
| -------------------- | ------------------------------------- |
| **Derleyici**        | Visual Studio 2022 (MSVC v143, C++17) |
| **İşletim Sistemi**  | Windows 10/11 (64-bit)                |
| **Yetki**            | Yönetici (Administrator)              |
| **Paket Yöneticisi** | winget (yeniden kurulum için)         |

### 🔨 Derleme

`LuckywareCleaner.sln` dosyasını Visual Studio 2022'de açın ve **Release** modunda derleyin. YARA kuralları (`rules/luckyware.yar`) otomatik olarak çıktı dizinine kopyalanır.

### 🚀 Kullanım Kılavuzu

> [!IMPORTANT]
> Programı **YÖNETİCİ OLARAK** çalıştırmanız **zorunludur**.

```bash
LuckywareCleaner.exe C:\ --block --patch-pe --remove --full-clean
```

<details>
<summary>⭐ <b>Komut Satırı Parametreleri</b></summary>

| Parametre          | Açıklama                                          |
| ------------------ | ------------------------------------------------- |
| `--block`          | C2 domainlerini HOSTS dosyasına kalıcı engeller   |
| `--unblock`        | HOSTS'tan Luckyware engellerini kaldırır          |
| `--patch-pe`       | Zararlı PE bölümlerinin çalıştırma bitini kapatır |
| `--remove`         | Enfekte SUO/VCXPROJ/temp dosyalarını temizler     |
| `--kill-process`   | Zararlı süreçleri sonlandırır                     |
| `--clean-registry` | Zararlı Run/RunOnce kayıtlarını siler             |
| `--clean-sdk`      | windows.h'dan VccLibaries'i kaldırır              |
| `--clean-imgui`    | imgui_impl_win32.cpp'den hex payload'ı kaldırır   |
| `--clean-discord`  | Discord enjeksiyonlarını temizler                 |
| `--clean-vcxproj`  | Sadece .vcxproj dosyalarındaki enjeksiyonu siler  |
| `--full-clean`     | Tüm temizleme modüllerini çalıştırır              |
| `--clear-cache`    | SHA256 önbelleğini (cache) temizler               |
| `--network`        | Tarama sırasında interneti keser (Kill-Switch)    |
| `--rules <dosya>`  | YARA kural dosyasının yolunu belirtir             |
| `--lang tr\|en`    | Dil seçimi                                        |
| `--debug`          | Hata ayıklama modu                                |

</details>

<details>
<summary>📝 <b>Diğer Örnekler</b></summary>

```bash
# Sadece tara (değişiklik yapma)
LuckywareCleaner.exe C:\

# İnteraktif mod (dil ve yol sorar)
LuckywareCleaner.exe

# Tüm korumalarla tam tarama
LuckywareCleaner.exe C:\ --block --patch-pe --remove --full-clean
```

</details>

> [!NOTE]
> İnteraktif modda (argümansız), program dil seçimi, yol girişi ve tehdit temizleme için onayınızı alarak sizi yönlendirir.

### ⚡ Hızlı Başlangıç

```bash
# 1. Projeyi Visual Studio'da derleyin (Release modu)
# 2. Komut istemcisini YÖNETİCİ olarak açın
# 3. Çıktı dizinine gidin
cd "Luckyware Cleaner Tool\bin\Release"

# 4. Tüm korumalarla tam tarama başlatın
LuckywareCleaner.exe C:\ --block --patch-pe --remove --full-clean

# 5. Ekran yönergelerini takip edin
# 6. Bilgisayarı yeniden başlatın ✓
```

### ⚠️ Önemli Uyarılar

> [!WARNING]
> - Programı **YÖNETİCİ OLARAK** çalıştırın
> - Tarama işlemi C: sürücüsü için **uzun sürebilir**
> - **Bitdefender Ultimate** ile ek tarama önerilir
> - İşlem bittikten sonra **TÜM şifrelerinizi değiştirin**

---

### 🆕 Recent Major Updates / Son Temel Güncellemeler
- **Advanced PE Detection**: No longer relies on extensions. Scans binary headers (`MZ`) of any file to find hidden payloads.
- **Advanced PE Tespiti**: Artık uzantılara güvenmez. Gizli dosyaları bulmak için herhangi bir dosyanın ikili başlıklarını (`MZ`) tarar.
- **Smart Script Cleaning**: Content-based verification for `.vbs` and `.ps1` files in `%TEMP%` to prevent false deletion of user scripts.
- **Akıllı Betik Temizleme**: Kullanıcı dosyalarının yanlışlıkla silinmesini önlemek için `%TEMP%` içindeki `.vbs` ve `.ps1` dosyaları için içerik tabanlı doğrulama.
- **Network Kill-Switch**: Optional internet disconnection during scans to prevent malware from communicating with C2 servers.
- **Ağ Kesici**: Zararlı yazılımın C2 sunucularıyla iletişim kurmasını önlemek için tarama sırasında isteğe bağlı internet kesintisi.
- **Deep VCXPROJ Scan**: Detects sophisticated Base64/VBScript decoding chains in Visual Studio project files.
- **Derin VCXPROJ Taraması**: Visual Studio proje dosyalarındaki karmaşık Base64/VBScript kod çözme zincirlerini tespit eder.
- **Improved Transparency**: Scanner now displays the specific malicious strings that triggered a YARA match.
- **Gelişmiş Şeffaflık**: Tarayıcı artık bir YARA eşleşmesini tetikleyen belirli zararlı dizeleri görüntüler.
- **Smart Path Targeting**: Focuses only on the user-specified folder for faster scans, while still covering system-wide hotspots for full-drive scans.
- **Akıllı Yol Hedefleme**: Daha hızlı tarama için sadece belirtilen klasöre odaklanır; tam sürücü taramaları için sistem kritik noktaları taranmaya devam eder.

---

## 📁 File Structure / Dosya Yapısı

```
Luckyware Cleaner Tool/
├── 📄 main.cpp                # Entry point / Ana giriş
├── 📄 scanner.hpp/.cpp        # Multi-threaded file scanner / Dosya tarayıcı
├── 📄 detector.hpp/.cpp       # Threat detection engine / Tehdit tespit motoru
├── 📄 cleaner.hpp/.cpp        # Auto-cleaner module / Otomatik temizleyici
├── 📄 network.hpp             # Network control module / İnternet kontrol modülü
├── 📄 yara_engine.hpp/.cpp    # YARA rule parser / YARA kural motoru
├── 📄 pe_check.hpp/.cpp       # PE file analysis / PE dosya analizi
├── 📄 ui.hpp                  # Console UI & progress bar / Konsol arayüzü
├── 📄 lang.hpp                # i18n translations / Dil çevirileri
├── 📄 obfuscate.hpp           # String security module / Güvenli dize modülü
├── 📄 LuckywareCleaner.sln    # Visual Studio solution
├── 📄 LuckywareCleaner.vcxproj # Visual Studio project
├── 📄 CMakeLists.txt          # CMake build config
├── 📖 ReadMe.MD               # This file / Bu dosya
└── 📂 rules/
    └── 🔒 luckyware.yar       # YARA rules / YARA kuralları
```

---

<div align="center">

**Made with 🛡️ to protect against Luckyware**

**Developer: victus & ziyy | github.com/SkyKubi0**

</div>
