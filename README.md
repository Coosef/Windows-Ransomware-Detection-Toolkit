# Windows Ransomware Detection Toolkit 🛡️

Taşınabilir (USB'den çalışan), **salt-okunur** fidye yazılımı (ransomware) tespit araç
seti. Bir makineye USB'yi takıp tek tıkla tarama yaptırır; bulguları rapor olarak
yine USB'ye yazar. Hiçbir dosyanızı silmez, değiştirmez veya karantinaya almaz —
yalnızca **tespit eder ve uyarır**.

> Portable, **read-only** ransomware detection toolkit. Plug the USB into a machine,
> run one click, get a report written back to the USB. It never deletes, changes or
> quarantines your files — it only **detects and alerts**.

---

## 🚀 Hızlı Başlangıç / Quick Start

1. Bu klasörün tamamını bir USB belleğe kopyalayın.
   *(Copy this whole folder onto a USB stick.)*
2. Hedef Windows makinesinde **`RunScan.bat`** dosyasına çift tıklayın.
   *(Double-click **`RunScan.bat`** on the target Windows machine.)*
3. Menüden bir seçenek seçin:

```
 [1]  Quick scan     Kullanıcı klasörleri (Masaüstü, Belgeler, İndirilenler...)
 [2]  Full scan      Tüm dahili diskler (yönetici izni ister)
 [3]  Live monitor   Gerçek-zamanlı erken uyarı (canary + ani değişiklik)
 [4]  Custom path    Seçtiğiniz bir klasör/sürücü
 [5]  Open reports   Rapor klasörünü aç
 [6]  Update         Güncel ransomware uzantılarını internetten çeker
 [7]  Identify       ID Ransomware / No More Ransom sitelerini açar
 [0]  Exit
```

Tarama bitince HTML raporu otomatik açılır ve `reports\` klasörüne
**TXT + JSON + HTML** olarak kaydedilir (yani USB'nizde kalır).

> PowerShell betikleri (`.ps1`) çift tıklayınca **çalışmaz**, Not Defteri'nde açılır.
> Her zaman **`RunScan.bat`** üzerinden başlatın. *(Always start via `RunScan.bat`.)*

### 🐧 Linux / macOS

Aynı araç seti Linux ve macOS'ta da çalışır — **tek bir Python 3 script'i**
(`ransomware_toolkit.py`) ile. Harici paket (pip) gerekmez; `python3` neredeyse tüm
dağıtımlarda hazır gelir. **Aynı `data/` klasörünü** kullanır, yani listeleri bir kez
güncellemek her iki platformu da günceller.

```bash
# USB'yi bağla, klasöre gir, çalıştır:
./run-scan.sh                          # interaktif menü
# veya doğrudan:
python3 ransomware_toolkit.py --mode quick --open-report
python3 ransomware_toolkit.py --mode custom --path /srv/share /mnt/data
python3 ransomware_toolkit.py --mode watch --path /home/me/Documents
python3 ransomware_toolkit.py --mode update
```

İlk çalıştırmada çalıştırma izni gerekebilir: `chmod +x run-scan.sh ransomware_toolkit.py`.
Linux fidye yazılımları (ESXiArgs, RansomEXX, LockBit-Linux, Royal, Cl0p ESXi vb.)
gerçek bir tehdittir; NAS/sunucu/ESXi tarafında da işe yarar. `full` modu `/proc`,
`/sys`, `/dev` gibi sözde dosya sistemlerini atlar; kök (`sudo`) ile daha kapsamlı tarar.

> Windows'ta PowerShell sürümü (`RunScan.bat`), Linux/macOS'ta Python sürümü
> (`run-scan.sh`) — ikisi aynı tespit mantığını ve aynı `data/` listelerini paylaşır.

---

## 🔍 Nasıl Tespit Eder? / Detection Layers

Tek bir disk gezintisiyle (verimli) her dosyaya **5 katman** uygulanır:

| # | Katman / Layer | Ne yakalar? / What it catches |
|---|----------------|-------------------------------|
| 1 | **Uzantı eşleştirme** / Extension match | Bilinen ransomware uzantıları (`data/extensions.txt`) — LockBit, Akira, Play, STOP/Djvu, WannaCry vb. |
| 2 | **Fidye notu adı** / Ransom-note name | `HOW TO DECRYPT FILES.txt`, `_readme.txt`, `RESTORE-MY-FILES.txt` gibi not dosyası desenleri (`data/ransom-note-names.txt`) |
| 3 | **Fidye notu içeriği** / Note content | Küçük metin dosyalarında "your files have been encrypted", "bitcoin", ".onion" gibi ifadeler (`data/note-keywords.txt`) — notu **doğrular** |
| 4 | **Entropi analizi** / Entropy | Shannon entropisi ile **şifrelenmiş dosya** tespiti. `.zip/.jpg/.mp4/.docx` gibi doğal yüksek-entropili türler hariç tutulur (yanlış pozitif önleme) |
| 5 | **Toplu değişiklik & yayılma** / Mass-change & spread | Kısa sürede toplu değiştirilen dosyalar, tek tuhaf uzantının bir klasörü doldurması (toplu şifreleme/yeniden adlandırma), aynı fidye notunun birçok klasöre bırakılması |

Modern aileler (LockBit 3.0, BlackCat/ALPHV, REvil, Conti...) çoğu zaman kurbana
özel **rastgele uzantı** kullanır; bunlar sabit listeyle yakalanamaz — 4. ve 5.
katmanlar (entropi + davranış) tam da bu boşluğu kapatmak için vardır.

### 🐤 Live monitor (canary) modu

`[3] Live monitor`, izlenen klasörlere gizli **tuzak (canary) dosyaları** yerleştirir
ve `FileSystemWatcher` ile klasörleri gerçek zamanlı izler. Şu üç durumda **anında
sesli alarm** verir:

- **CANARY TRIPPED** — bir tuzak dosya değiştirilir/silinir/yeniden adlandırılırsa
  (aktif şifrelemenin neredeyse kesin işareti),
- **CHANGE BURST** — birkaç saniye içinde çok sayıda dosya değişikliği olursa,
- **SUSPICIOUS FILE** — bilinen bir ransomware uzantısı veya fidye notu adıyla yeni
  bir dosya belirirse.

Tuzak dosyalar benzersiz bir imza satırı taşır; program durunca (veya bir sonraki
başlatmada) yalnızca **kendi** tuzaklarını güvenle temizler — asla birikmezler.

---

## 🧪 Sonuç / Verdict

| Sonuç | Anlamı |
|-------|--------|
| `CLEAN` | Gösterge bulunamadı (çıkış kodu 0) |
| `SUSPICIOUS - REVIEW NEEDED` | Orta seviye bulgular, incelenmeli (çıkış kodu 1) |
| `RANSOMWARE INDICATORS FOUND` | Yüksek seviye göstergeler (çıkış kodu 2) |

Çıkış kodları, betiği otomasyon/görev zamanlayıcıda kullanmayı kolaylaştırır.

---

## ⚙️ Gelişmiş Kullanım / Advanced (PowerShell)

`RunScan.bat` sadece çift-tık kolaylığıdır; her şey **tek script** `RansomwareToolkit.ps1`
içindedir ve `-Mode` ile doğrudan da çağrılabilir:

```powershell
# Menü olmadan doğrudan hızlı tarama + raporu aç
.\RansomwareToolkit.ps1 -Mode Quick -OpenReport

# Tüm dahili diskler (yönetici PowerShell önerilir)
.\RansomwareToolkit.ps1 -Mode Full

# Belirli yolları tara
.\RansomwareToolkit.ps1 -Mode Custom -Path 'D:\Shares','E:\'

# Tarama ayarları
.\RansomwareToolkit.ps1 -Mode Custom -Path 'D:\' -RecentHours 12 `
        -MassChangeThreshold 30 -EntropyThreshold 7.9 -MaxFileSizeMB 100

# Canlı izleme (özel klasör + hassas eşik)
.\RansomwareToolkit.ps1 -Mode Watch -Path 'D:\Shares\Finance' -BurstThreshold 15 -BurstWindowSec 5

# Argümansız çalıştırınca interaktif menü açılır (RunScan.bat'in yaptığı budur)
.\RansomwareToolkit.ps1
```

**Öne çıkan parametreler:**

- `-Quick` / `-Full` / `-Path` — tarama kapsamı
- `-RecentHours` (24) — "son X saatte toplu değişiklik" penceresi
- `-MassChangeThreshold` (40) — bir klasörde kaç yeni değişiklik "patlama" sayılır
- `-EntropyThreshold` (7.8) — bunun üzeri entropi "muhtemelen şifreli"
- `-NoEntropy` — entropi katmanını kapat (en hızlı)
- `-MaxFileSizeMB` (150) — bu boyutun üstündeki dosyalarda entropi/içerik atlanır
- `-OutputDir` / `-DataDir` — rapor ve IOC klasörü konumu

---

## 🔄 Listeleri Güncelleme / Updating the definitions

Tespit verileri kod içinde gömülü değil, `data\` klasöründe düz metin dosyalarındadır.

### Otomatik güncelleme — menü `[6]`
`[6] Update` seçeneği (veya `-Mode Update`) internetten **güncel ransomware
uzantılarını** çeker. İki tür kaynak vardır (`data/update-sources.txt` içinde
tanımlı, düzenlenebilir):

- **`trusted`** — senin kendi GitHub repon. İndirilen dosya doğrulanıp yerini alır
  (eski hâli `.bak` olarak yedeklenir).
- **`community`** — haftalık güncellenen topluluk listeleri
  ([dannyroemhild](https://github.com/dannyroemhild/ransomware-fileext-list),
  [thephoton](https://github.com/thephoton/ransomware)). Bunlar **sert filtreden**
  geçer (yalnızca temiz `.ext` girişleri; `*.crypto*` gibi geniş desenler, `.007`
  gibi bölünmüş-arşivle çakışan sayısal uzantılar ve `.swp/.lock/.key` gibi normal
  dosya uzantıları elenir) ve `data/extensions-auto.txt`'ye **birleştirilir**
  (senin küratörlü `extensions.txt`'ne asla dokunmaz, hiçbir şeyi silmez).

> **İki güven seviyesi (yanlış pozitifleri önler):** Elle küratörlüğü yapılan
> `extensions.txt` **yüksek güven** → dosya adından işaretler. Topluluktan gelen
> `extensions-auto.txt` **düşük güven** → yalnızca dosya **aynı zamanda yüksek
> entropiliyse** (gerçekten şifreliyse) işaretlenir. Böylece binlerce topluluk
> uzantısı tespiti güçlendirir ama `.lock`/`.swp` yanlış pozitifi üretmez.

> ⚠️ Güncellemeyi **temiz, internete bağlı bir makinede** yapıp USB'yi tazele;
> izole/enfekte bir hostta değil.

### Aile tanıma & çözücü bulma — menü `[7]`
Tarama sonrası araç, bulunan uzantı/notları çevrimdışı bir eşleme
(`data/families.json`) ile karşılaştırır ve **muhtemel aileyi + ücretsiz çözücü
linkini** raporda gösterir (ör. STOP/Djvu → Emsisoft). `[7] Identify` seçeneği
[ID Ransomware](https://id-ransomware.malwarehunterteam.com/) ve
[No More Ransom – Crypto Sheriff](https://www.nomoreransom.org/crypto-sheriff.php)
sayfalarını tarayıcıda açar; dosyayı **sen manuel** yüklersin.

> 🔒 **Gizlilik:** Araç dosyaları otomatik olarak hiçbir yere yüklemez. Bu siteler
> üçüncü taraftır; hassas veri yüklemeyin. Şifreli dosyalar (ciphertext) ve fidye
> notu kimlik tespiti için genelde güvenlidir. (ID Ransomware/No More Ransom'ın
> halka açık API'si yoktur, bu yüzden tam otomasyon yerine "tarayıcıda aç" yaklaşımı
> kullanılır.)

### Elle güncelleme
Yeni bir aileyi elle eklemek için ilgili dosyaya bir satır ekleyin:

- `data/extensions.txt` — ransomware dosya uzantıları (`.ext` veya `*joker*`)
- `data/ransom-note-names.txt` — fidye notu dosya adı desenleri
- `data/note-keywords.txt` — fidye notu içerik anahtar kelimeleri
- `data/families.json` — uzantı → aile → çözücü eşlemesi

`#` ile başlayan satırlar yorumdur.

---

## 🚑 Yüksek bulgu çıktıysa ne yapmalı? / If indicators are found

1. **Ağ/Wi-Fi bağlantısını hemen kesin** (yayılmayı durdurur).
2. Makineyi **yeniden başlatmayın**, dosyaları elle silmeyin.
3. **Fidye ödemeyin.**
4. `reports\` içindeki raporu (kanıt olarak) saklayın.
5. Kurumsal AV/EDR veya olay müdahale (IR) ekibinize ulaşın.
6. Temiz yedeklerden geri yükleyin.

---

## 📁 Proje Yapısı / Layout

```
Windows-Ransomware-Detection-Toolkit/
├── RunScan.bat              # Windows başlatıcı (çift-tık)
├── RansomwareToolkit.ps1    # Windows motoru: menü + tarama + izleme + güncelleme
├── run-scan.sh              # Linux/macOS başlatıcı
├── ransomware_toolkit.py    # Linux/macOS motoru (Python 3, aynı özellikler)
├── data/                    # Güncellenebilir IOC listeleri (İKİ platform ortak)
│   ├── extensions.txt          # küratörlü uzantılar (yüksek güven)
│   ├── extensions-auto.txt     # topluluktan çekilen uzantılar (düşük güven)
│   ├── ransom-note-names.txt
│   ├── note-keywords.txt
│   ├── families.json           # uzantı → aile → çözücü eşlemesi
│   └── update-sources.txt      # güncelleme kaynakları (düzenlenebilir)
├── reports/                 # Çıktı raporları (TXT/JSON/HTML) buraya yazılır
├── legacy/                  # Eski v1/v2 betikleri (arşiv)
└── README.md
```

> **Neden hâlâ bir `.bat` var?** Windows'ta bir `.ps1` dosyasına çift tıklayınca
> çalışmaz, Not Defteri'nde açılır. `RunScan.bat` yalnızca tek script'i başlatan
> 2 satırlık bir sarmalayıcıdır. Sen sadece **`RunScan.bat`**'e çift tıklarsın;
> gerisi `RansomwareToolkit.ps1` içindeki menüden döner.

**Gereksinim:**
- **Windows:** yerleşik **PowerShell 5.1+** (Windows 7/10/11) veya PowerShell 7. Harici bağımlılık yok.
- **Linux / macOS:** yerleşik **Python 3.6+**. Harici paket (pip) yok, yalnızca standart kütüphane.

Her iki sürüm de aynı `data/` listelerini ve aynı çok katmanlı tespit mantığını kullanır.

---

## ⚠️ Feragatname / Disclaimer

Bu araçlar, siber güvenlik duruşunuzu güçlendirmek için **yardımcı** bir önlemdir;
profesyonel AV/EDR çözümlerinin yerine geçmez. Herhangi bir ortamda çalıştırmadan önce
uygun yetkiye sahip olduğunuzdan emin olun. Araç salt-okunurdur ve verinizi değiştirmez;
yine de kullanımından doğabilecek sonuçlardan geliştirici sorumlu tutulamaz.

> These tools are a **supplementary** measure and are not a replacement for professional
> AV/EDR. Ensure you have proper authorization before running them. The tool is read-only
> and does not modify your data, but the author assumes no liability for its use.

## 📄 Lisans / License

MIT — bkz. [LICENSE](LICENSE).
