# Linux yerel kurulumu

[English](INSTALL_LINUX.md) • **Türkçe**

[İngilizce README](../README.md) ya da [Türkçe README](../README.tr.md)
içindeki tek komut Python'u, bağımlılıkları, uygulamayı, bir uygulamalar menüsü
kısayolunu ve `threatfusion-ai` terminal komutunu kurar. Normal kullanıcınla
çalışır: sudo, sistem Python'unda değişiklik, Git, derleyici, Docker ya da bulut
hesabı gerekmez. Tarayıcı arayüzü yalnızca **127.0.0.1** adresine bağlanır. Bu
kurulum herkese açık bir web sitesi oluşturmaz ya da yeniden başlatmaz.

## Desteklenen sistemler

**Linux x86_64, glibc 2.28+**; Python ya da Git bulunmayan temiz Debian 12 ve
Ubuntu 24.04 imajlarında test edildi. ARM, Alpine/musl, Windows ve macOS bu
kurulum aracıyla desteklenmez. İşletim sisteminde Bash, curl ya da wget, çalışan
HTTPS CA sertifikaları, tar, coreutils ve util-linux (`flock`, `getconf`)
bulunmalıdır. Kurulum için GitHub/PyPI'a internet erişimi ve yaklaşık 2 GB boş
alan, ayrıca indirilen CTI için yer gerekir. Ekransız (headless) bir makinede
komutun sonuna `--no-browser` ekle.

## İlk kullanım: gerçek istihbarat, kendi anahtarların

Yeni kurulumlar **gerçek CTI modunda** açılır; sözcüksel ML alan adı skoru
kapalıdır. Önbellek başta boştur; boş bir önbellek ya da eşleşme olmaması
güvenli olduğunu göstermez. Yeni kurulumda önce **Kurulum ve CTI güncellemeleri**
sayfası (kenar çubuğundaki **Sayfalar** listesi) açılır:

1. Varsa kendi ThreatFox ve URLhaus API anahtarlarını gir; tek bir ücretsiz
   abuse.ch anahtarı ikisini de kapsar. SGB anahtarsız çalışır.
2. **Anahtarları uygula**'yı seç. Varsayılan olarak anahtarlar geçerli tarayıcı
   oturumunda kalır.
3. **CTI verilerini şimdi güncelle**'ye tıkla. Her kaynak bağımsız güncellenir.
   Başarısız bir kaynak önceki önbelleğini korur; panel atlanan kaynakları,
   hataları ve güvenli sayıları gösterir.
4. Hızlı sorgu yap ya da telemetri yükle. Önbellek güncellendikten sonra analizi
   yeniden çalıştır: daha önce gösterilen sonuçlar anlık görüntülerdir.

Kaynaklara erişim ve kaynakların sürekliliği garanti değildir. Uygulama IOC
hedeflerini ziyaret etmez. İzin verilen beslemeleri indirmek yeniden dağıtım
hakkı vermez; bkz. [veri kaynakları](DATA_SOURCES.tr.md).

**Anahtarları bu bilgisayara kaydet** isteğe bağlıdır ve varsayılan olarak
seçili değildir. Özel **0700** kurulum dizininin içine yalnızca sahibinin
okuyabileceği **0600 düz metin** bir `credentials.json` yazar. Bu şifreleme
değil, erişimi kısıtlanmış bir depolamadır. Kaydedilen anahtarlar tarayıcıdaki
parola alanlarına geri doldurulmaz, komut argümanlarına eklenmez, kayıtlara
yazılmaz, dışa aktarılmaz, GitHub'a kopyalanmaz ya da Docker imajlarına girmez.
**Kayıtlı ve oturumdaki anahtarları unut**, uygulamanın kayıtlı dosyasını ve
geçerli tarayıcı oturumunun anahtar seçimini kaldırır. Açık diğer tarayıcı
oturumlarının kendi belleği vardır; onların seçimlerini silmek için o sekmeleri
kapat. Yedek olarak hiçbir geliştirici anahtarı, `.env`, Streamlit secret ya da
özel geliştirme önbelleği kullanılmaz. Ayrı geliştirici CLI ortam seçenekleri
yönetilen kurulumdan ayrı kalır.

## Otomatik güncellemeler

**Uygulama çalışırken otomatik güncelle** seçeneğini açıp bir aralık
(**6, 12 ya da 24 saat**) kaydedene kadar güncellemeler elle yapılır. Başlatıcı
bu zamanlayıcıyı tarayıcı yenilemelerinden ve sekmelerden bağımsız olarak
yönetir. Yalnızca **kayıtlı anahtarları ve herkese açık kaynakları** kullanır;
başka bir tarayıcı oturumunun kaydedilmemiş anahtarlarını kullanmaz.

- Zamanı gelince toplama başlar; kaçırılan süre varsa uygulamanın bir sonraki
  açılışında da.
- Güncel kaynaklar atlanır.
- Çevrimdışıyken sık tekrar döngülerini önlemek için denemeler başarısız olsa da
  kaydedilir.
- Elle, CLI ile ve otomatik güncelleme aynı engellemeyen işlem kilidini paylaşır.
- Tarayıcı sekmesini kapatmak yerel sunucuyu ve zamanlayıcıyı çalışır bırakır.
  Uygulamayı durdurmak ikisini de durdurur. Cron, oturum açılışında otomatik
  başlatma ya da sistem arka plan servisi eklenmez; uygulama dururken hiçbir şey
  indirilmez.

Ayar ve durum dosyaları API anahtarlarını ya da yüklenen telemetriyi değil,
yapılandırmayı ve toplu sayıları içerir. CTI önbellekleri yerelde kalır ve depo
sürümlerine asla eklenmez. Sentetik demo verisi ve gerçek CTI ayrı veritabanları
kullanır.

## Yeniden açma ve durdurma

Masaüstü uygulamalar menüsünden **ThreatFusion AI**'yı seç ya da yeni bir
terminal açıp şunu çalıştır:

```bash
threatfusion-ai
```

Kısayol, yerel uygulamayı yöneten bir terminal ve ardından tarayıcını açar.
Bağımlılıkları yeniden kurmaz ve mevcut önbelleği kullanmak için internet
gerektirmez. Seçilen çalışma modu hatırlanır. Desteklenen yönetim komutları:

```bash
threatfusion-ai status    # çalışma durumu ve localhost adresi
threatfusion-ai refresh   # kayıtlı anahtarlar/herkese açık kaynaklarla gerçek CTI güncellemesi
threatfusion-ai stop      # bu kurulumun sunucusunu ve zamanlayıcısını durdur
```

Web panelindeki **Yerel uygulamayı kapat** düğmesini, Ctrl+C'yi kullanabilir ya
da yöneten terminali kapatabilirsin. Ctrl+C/SIGTERM/SIGHUP alt işlemleri
temizler. Yalnızca bu kurulumu kontrol eden özel bir Unix soketi kullanılır;
işlem sonlandırmak için eski PID dosyalarına güvenilmez. Yinelenen başlatmalar,
çalışan bir sunucuyu ya da başka bir uygulamanın kullandığı bir portu
etkilemeden reddedilir.

Başlatıcının tam yolu her zaman kullanılabilir; PATH'i henüz yenilenmemiş, zaten
açık bir terminalde de:

```bash
"${XDG_DATA_HOME:-$HOME/.local/share}/threatfusion-ai/start"
```

Kurulum aracı `~/.local/bin/threatfusion-ai` komutunu ve bir XDG `.desktop`
girdisini kaydeder. Gerekirse kullanıcının profil dosyasına ve Bash/Zsh
başlangıç dosyasına (ya da bir Fish conf.d dosyasına) işaretli bir PATH satırı
ekler; mevcut içerik korunur. İlgisiz komutlar, masaüstü girdileri ve sembolik
bağlantılı başlangıç dosyaları değiştirilmez. İlgisiz bir kısayol kaydı
engelliyorsa yazdırılan tam başlatıcı yolunu kullan. `--no-integrations`
komut/menü/kabuk kaydını atlar.

## Çalışma modeli ve demo

Gerçek CTI modu sentetik demo modelini ölçülmüş bir dedektör yerine **kullanmaz**.
Kurulum, önceden eğitilmiş bir dedektör içermez; yalnızca davranış modelinin
herkese açık öznitelik paketiyle gelir ve model **Deneysel ML** sekmesinde bu
bilgisayarda eğitilir. Sözcüksel ve davranış modeli deneyleri ile sonuçları için
bkz. [ML_DATASET.md](evidence/ML_DATASET.md) (İngilizce).

Arayüzü çevrimdışı keşfetmek için çalışma modu seçicisinden **Sentetik demo**'yu
seç ya da:

```bash
threatfusion-ai --mode demo
```

Demo, ayrılmış dört örnek gösterge ve sağlama toplamıyla sabitlenmiş, yalnızca
sentetik bir model üretir. `known-threat.example` adresini dene. Skoru ölçülmüş
bir zararlı yazılım tespit başarımı değildir. Mod değiştirmek eski arayüz
sonuçlarını temizler ve iki veritabanını da korur. Gerçek moda dönmek demo
modelini yeniden kapatır.

## Kurulum ayrıntıları ve güncelleme

Varsayılan konum: `${XDG_DATA_HOME:-$HOME/.local/share}/threatfusion-ai`.
Özel Python **3.12.14**, uv **0.12.23** (sabit arşiv sağlama toplamı), hash'i
doğrulanan 49 çalışma zamanı paketi, değişmez kaynak sürümleri ve çalışma verisi
burada tutulur. Orijinal geliştirme kopyası, sanal ortamı, modeller ve veriler
değiştirilmez. Dizin dışına çıkan yollar, bağlantılar, özel dosyalar ve aşırı
boyutlar içeren kaynak arşivleri reddedilir. Devralınan Python/paket yöneticisi
ayarları temizlenir.

En son `main` kaynağını kurmak için kurulum komutunu yeniden çalıştır; mevcut
CTI, ayarlar ve isteğe bağlı kayıtlı anahtarlar korunur. Bu güncellemeyi mevcut
kurulumu durdurduktan sonra yap. Çevrimdışı yeniden başlatmalar kurulu kaynak
sürümünü korur; kod güncellemelerini sessizce indirmez.

README komutunun son `--` işaretinden sonra seçenek ekleyebilirsin:

```text
--prepare-only                 # sunucuyu başlatmadan kur/kontrol et
--no-browser                   # tarayıcı açmadan localhost adresini yazdır
--no-integrations              # masaüstü/terminal/kabuk değişikliği yapma
--install-dir "/tam/yol"       # kullanıcıya ait ayrı bir kurulum dizini
--mode demo                    # ilk kullanımda açıkça sentetik modu iste
--port 18501                   # sabit, ayrıcalıksız loopback portu; doluysa hata ver
--ref <tam-commit-sha>         # sabit kaynak sürümü
```

`--mode cti-only` ile birlikte `--refresh-cti`, açılışta kayıtlı anahtarlar ve
herkese açık kaynaklarla bir güncelleme ister. Normal etkileşimli panel
önerilir. Başlatıcı seçenekleri ayrıca `--mode`, `--port`, `--prepare-only` ve
`--no-browser` içerir. Yalnızca kurulumda geçerli `--ref`, `--source-dir` ve
`--no-integrations` normal başlatıcı seçenekleri değildir. `--source-dir`
yalnızca geliştiriciler/CI içindir.

İlk çalıştırma 8501–8600 aralığında boş bir port seçer ve tarayıcıyı açmadan
önce sağlık kontrolü yapar. Başarısız bir kaynak güncellemesi hiçbir ML
modelini terfi ettirmez ya da eşik ayarlamaz. Bu yönetilen profilde geçmiş ve
telemetri oturumla sınırlı kalır; `THREATFUSION_PUBLIC_MODE` gizlilik bayrağı
ağa açık erişim anlamına gelmez.

## Kaldırma

Uygulamayı durdurup kurulumu tamamen silmek için:

```bash
threatfusion-ai stop; rm -rf ~/.local/share/threatfusion-ai ~/.local/bin/threatfusion-ai ~/.local/share/applications/io.github.ConquestorYa.ThreatFusionAI.desktop
```

Kurulumu `--install-dir` ile başka bir yere yaptıysan ilk yol yerine o dizini
yaz. Bu komut kurulum dizinindeki **her şeyi** siler: kayıtlı API anahtarlarını,
CTI önbelleğini, toplayıcı verisini, **Tanıyorum/Şüpheli** işaretlerini ve
Deneysel ML'in öğrendiği günleri. Bunları korumak istiyorsan önce dizini
yedekle. Toplayıcıyı ayrı bir terminalde çalıştırıyorsan önce Ctrl+C ile
durdur.

Kurulum aracının profil dosyalarına eklediği PATH satırı (`# Managed by ThreatFusion AI installer`
işaretli, `~/.local/bin`'i PATH'e ekler) zararsızdır ve kalabilir; istersen
`~/.profile` ve `~/.bashrc` (ya da `~/.zshrc`) dosyasından elle silebilirsin.
Fish kullanıyorsan `~/.config/fish/conf.d/threatfusion.fish` dosyasını da sil.
Zeek sensörü (Docker kapsayıcısı ve kayıt klasörü) ayrı kurulur; onu kaldırmak
için [Zeek sensör kurulumu](ZEEK_SETUP.tr.md) belgesine bak.

## Otomatik Zeek bağlantıları ve DNS

Önce döndürülmüş kayıtlar yazan bir Zeek sensörü kur:
[Zeek sensör kurulumu](ZEEK_SETUP.tr.md). Gerçek CTI modunda ayrı bir terminal
kullan:

```bash
threatfusion-ai collect --input-dir /zeek/kayitlarinin/tam/yolu
```

Yerel **Toplanan bağlantılar** sayfası özel durumdan yenilenir. Tamamlanmış TSV
kayıtları/arşivleri bir kez içe aktarılır; açık kayıtlar kapanmayı bekler.
TCP/UDP `dns.log` arşivleri aynı sayfadaki **Toplanan DNS gözlemleri** bölümünü
doldurur; sorgular bağlantı kanıtından ayrı tutulur. Şema-1 toplayıcı durumu
yükseltmeden önce özel olarak yedeklenir. Bkz.
[DNS geçişi ve sınırları](evidence/DNS_COLLECTION.md) (İngilizce). Ctrl+C
toplamayı durdurur; komutu yeniden çalıştırmak tekrar oluşturmadan devam eder.
Web uygulaması ve toplayıcının ömürleri ayrıdır. Arka plan sistem servisi
kurulmaz. Neyin işaretlendiği, sınırlar ve inceleme
[kullanım kılavuzunda](USER_GUIDE.tr.md#toplayıcı) anlatılır.

Yüklenen telemetri oturumla sınırlı kalır. Bu toplayıcıyı kullanmayı seçmek,
türlendirilmiş bağlantı/DNS kanıtını kurulumun `collector/` dizininde, sınırlı
saklama süresiyle özel olarak tutar. Hiçbir şey yüklenmez ya da paylaşılan
analist geçmişine eklenmez.

Gerçek IP'ler, yalnızca sahibinin okuyabildiği yerel bir eşlemeden kendi
ekranında gösterilir (**Gözlenen cihaz IP'lerini yerelde göster; indirmeler
takma adları korur**); indirilen raporlar takma adları korur. Güncellemeden önce
başlatılmış bir toplayıcı bu eşlemeyi yeniden başlatıldıktan sonra oluşturur.
İnceleme işaretleri (`review-labels.json`) ve Deneysel ML sekmesinin hedef
belleği (`ml/baseline.json`) kurulum dizininde yalnızca sahibinin okuyabildiği
dosyalardır.

## Sorun giderme

- Geçerli terminalde komut yok: yeni bir terminal aç ya da başlatıcının tam
  yolunu kullan. Aynı adlı ilgisiz bir komut bilerek korunur.
- Kaynak atlandı: kendi anahtarını girip **Anahtarları uygula**'ya bas; otomatik/CLI
  güncellemenin kullanmasını istiyorsan kaydet. Sentetik demoyu keşfetmek için
  anahtar gerekmez.
- Güncelleme başarısız: ağ/kaynak erişimini ve anahtarın geçerliliğini kontrol
  et. Kaynak hatasında mevcut önbellek korunur; durum ekranı anahtar içeren ham
  HTTP hatalarını asla yazdırmaz.
- İzin hatası: yönetilen dosyalar senin kullanıcına ait ve özel olmalıdır.
  Anahtar dosyasını 0644'e açma ve kurulumu root olarak çalıştırma.
- Zaten çalışıyor: adres için `threatfusion-ai status` kullan ya da önce durdur.
- Sabit port dolu: başka bir `--port` seç; uygulama portu kullanan işlemi asla
  sonlandırmaz.
- Başlatma `AF_UNIX path too long` hatasıyla duruyor: kurulum yolu özel kontrol
  soketi (`<kurulum>/control.sock`, Linux sınırı 108 bayt) için fazla uzun.
  Daha kısa bir `--install-dir` kullan (yaklaşık 90 karakter ya da daha az);
  varsayılan `~/.local/share/threatfusion-ai` normal ev klasörlerinde sorun
  çıkarmaz.
