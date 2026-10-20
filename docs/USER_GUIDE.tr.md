# Kullanım kılavuzu

[English](USER_GUIDE.md) • **Türkçe**

ThreatFusion tek bir soruyu yanıtlar: **hangi cihaz hangi hedefle konuştu ve bu
konuşmalardan hangileri daha yakından bakmayı hak ediyor?** Zeek kayıtlarını
okur, hedefleri tehdit istihbaratı (CTI) listeleriyle karşılaştırır ve zararlı
yazılımın komuta-kontrol (C2) trafiğine özgü birkaç davranışı kontrol eder. Her
işaret neden konduğunu söyler. İşaret kontrol etmek için bir sebeptir, asla
bulaşma kanıtı değildir.

Önce kur: [Linux kurulumu](INSTALL_LINUX.tr.md). Kayıt üretmek için:
[Zeek sensör kurulumu](ZEEK_SETUP.tr.md).

## Sayfalar

| Sayfa | Ne için |
| --- | --- |
| **Toplanan bağlantılar** | Zeek sensörünün kayıtlarını sürekli izle. Ana sayfa. |
| **Telemetriyi analiz et** | Tek bir dosya yükle (Zeek, DNS CSV, PCAP, Pi-hole, AdGuard, Suricata…) ve bir kez analiz et. |
| **Hızlı sorgu** | Tek bir URL, alan adı ya da IP'yi ziyaret etmeden yerel CTI listelerinde kontrol et. |
| **Kurulum ve CTI güncellemeleri** | Modu seç, API anahtarlarını gir, CTI listelerini güncelle, güncellemeleri zamanla. |
| **Model değerlendirmesi** | Davranış modeli bu bilgisayarda eğitildikten sonra görünür; modelin önceden ilan edilmiş testlerini ve sınırlarını gösterir. |
| **Analiz geçmişi** | Yalnızca demo modunda; varsayılan gerçek CTI modunda kapalıdır. |

Kenar çubuğu her CTI kaynağının durumunu gösterir. Sağ üstten İngilizce ya da
Türkçe dil ve açık ya da koyu tema seçilebilir.

## CTI kaynakları

| Kaynak | Anahtar | İçerik |
| --- | --- | --- |
| SGB (T.C. Siber Güvenlik Başkanlığı) | Gerekmez | Türkiye'de bildirilen zararlı alan adları ve IP'ler |
| ThreatFox (abuse.ch) | Ücretsiz abuse.ch anahtarı | Zararlı yazılım komuta-kontrol sunucuları ve diğer göstergeler (IOC) |
| URLhaus (abuse.ch) | Aynı anahtar | Zararlı yazılım indirme URL'leri |

[auth.abuse.ch](https://auth.abuse.ch/) adresinden alınan tek bir ücretsiz
anahtar iki abuse.ch kaynağını da açar. Anahtarlar, yalnızca senin
okuyabileceğin özel bir dosyaya kaydetmeyi seçmedikçe tarayıcı oturumunda
kalır. Başarısız bir güncelleme önceki veriyi korur.

Aynı güncelleme, anahtarsız iki herkese açık bağlam listesini de haftada bir
indirir: Tranco popüler site listesi ve iptoasn.com IP sahibi tablosu (bir
adresin hangi ağa ve o ağın hangi kayıt ülkesine ait olduğu). Bunlar tehdit
verisi değil bağlamdır; bu listelerdeki aramalar bilgisayarında kalır.

## Toplayıcı

```bash
threatfusion-ai collect --input-dir /zeek/kayitlarinin/tam/yolu
```

Toplayıcı klasörü 10 saniyede bir kontrol eder ve **tamamlanmış** her Zeek
kaydını içe aktarır: adı `conn.`/`dns.` ile (ya da `_` veya `-` ile) başlayan,
`.log` ya da `.log.gz` ile biten ve son satırı `#close` ile başlayan dosyalar.
Hâlâ yazılmakta olan dosyalar döndürülene kadar bekler. Alt klasörler taranır;
ZeekControl'ün `current` klasörü gibi sembolik bağlantılı klasörler atlanır.
Her sensör için ayrı bir durum kullan.

- Son **24 saatin** kanıtını tutar (`--window-hours`, 1–168).
- Ctrl+C durdurur; aynı komutu yeniden çalıştırmak kontrol noktalarından devam
  eder.
- Web uygulamasından ayrı çalışır. `threatfusion-ai stop` web uygulamasını
  durdurur, toplayıcıyı durdurmaz. Oturum açılışında hiçbir şey kendiliğinden
  başlamaz.
- Kurulumun CTI önbelleğini kullanır ve CTI güncellemelerini bir sonraki
  taramada alır. Bir güncelleme önbelleğe yazıyorsa tarama önceki göstergeleri
  kullanır ve sayfa bunu belirtir.
- Toplayıcının kendisi ML kullanmaz. Sayfadaki **Deneysel ML** sekmesi toplanan
  kayıtlardan kendi görünümünü oluşturur ve davranış modelini bu bilgisayarda
  eğitir (aşağıya bak).

Sayfa 10 saniyede bir yenilenir; eskimiş anlık görüntüler, reddedilen dosyalar ve
azalan kapsam için uyarır.

### Neler işaretlenir

Bağlantılar **cihaz → hedef IP ve port** olarak gruplanır.

| Kontrol | Kural | Neden önemli |
| --- | --- | --- |
| CTI eşleşmesi | Hedef IP bir CTI listesinde | Bilinen zararlı altyapı |
| Uzun oturum | Tek bir iki yönlü TCP oturumu en az 1 saat sürer | Kontrol kanalları çoğu zaman açık tutulur |
| Düzenli tekrar | En az 30 dakika boyunca, çok düzenli aralıklarla en az 20 bağlantı | Zararlı yazılım bir zamanlayıcıyla "haber verir" |
| Başarısız denemeler | Beş dakika içinde en az 20 farklı port/hosta yanıtsız ya da reddedilen TCP denemeleri veya en az 30 tekrarlanan başarısızlık | Tarama ya da ulaşılamayan bir sunucuyu denemeye devam eden bir program |

DNS gözlemleri **cihaz → alan adı** olarak gruplanır ve şu durumlarda
**İncele** düzeyine çıkar:

- alan adı bir CTI listesindedir (**Bilinen tehdit**) ya da yanıt IP'lerinden
  biri veya listelenmiş bir URL'nin ana makine adı listededir (CTI bağlamı);
- sorgular düzenli aralıklarla tekrarlanır (aynı 20 sorgu / 30 dakika alt
  sınırı); ya da
- en az iki hacim sinyali birlikte görülür: çok sayıda sorgu, çok sayıda
  istemci, değişen yanıt IP'leri, çok sayıda sorgu türü ya da kısa sürede bir
  patlama.

Sık "böyle bir alan adı yok" yanıtları, değişen yanıtlar ve rastgele görünen
adlar bağlam olarak gösterilir; tek başlarına bir grubu yükseltmez.

**Sıradan trafiği İncele listesinin dışında tutan bağlam** (ilk gerçek trafik
testinden sonra eklendi, [sonuçlar](evidence/REAL_TRAFFIC_EVALUATION.md#arm-a-first-24-hours-results), İngilizce):

- **Yerel adlar** (`.local` mDNS/DNS-SD duyuruları, ters `*.arpa` sorguları,
  yerel bölgeler) bir CTI listesi eşleşmedikçe **Gözlem** düzeyinde kalır.
- **Popüler siteler.** CTI güncellemesi haftada bir ve anahtarsız olarak
  herkese açık [Tranco](https://tranco-list.eu/) ilk 100.000 listesini ve
  [Public Suffix List](https://publicsuffix.org/)'i de indirir. Bir adın kayıtlı
  alan adı ilk 100.000 içindeyse hacim ve değişen yanıt sinyalleri Gözlem
  düzeyinde kalır; o sitedeki listelenmiş bir URL ise bağlam olarak gösterilir
  (site listelenmiş bir dosyayı barındırır, kendisi listede değildir). Bir
  kullanıcının paylaşımlı bir platformdaki kendi alt alan adı (dinamik DNS,
  kullanıcı sayfaları, tüneller) ayrı bir kayıtlı alan adıdır ve popüler
  **sayılmaz**. DNS adlarının hepsi popüler site olan bir bağlantı, bu neden
  gösterilerek gözlem olarak kalır. CTI listesindeki tam bir alan adı ya da
  adres her zaman önceliklidir.
- **Sınırlılık.** Saldırganlar da popüler servisleri kullanır; bu bağlam,
  kullanılabilir bir liste karşılığında o görünürlüğün bir kısmından vazgeçer.
  Etkisi henüz yeni günlerde ölçülmedi.

Bakılması gereken gruplar **İncele** olarak görünür; geri kalan her şey
**Gözlem** olarak görünür kalır. CTI eşleşmesi olan bir bağlantı, davranışı
Gözlem düzeyinde olsa bile işaretlenir ve her zaman gösterilir; CTI eşleşmesi
olan DNS grupları **Öncelikle araştır** olarak en üste çıkar. Başarısız deneme
desenlerinin kendi listesi vardır. Normal yazılımlar da bu kurallara uyabilir:
güncelleyiciler zamanlayıcıyla tekrarlar, sohbet ve bildirim uygulamaları uzun
oturumlar tutar. Bu yüzden her satır nedenini açıklar ve sonuç bir alarm değil,
kontrol edilecekler kuyruğudur.

### Üç sekme

**Bakılacaklar** her öğe için bir satır içeren bir alarm listesidir: ad
(bağlantılar için adrese işaret eden DNS adları), *Uzun bağlantı · 2,0 sa açık*
ya da *Sık sorgu · 66 sorgu* gibi kısa bir etiket, altında ağ sahibiyle birlikte
cihaz IP → hedef IP:port (örneğin *FASTLY · US*; ülke, sunucunun bulunduğu yer
değil ağın kayıtlı olduğu yerdir) ve zaman. Tehdit listesindeki öğeler en üstte
gelir (🔴). **Neden? Ne yapmalı?** nedeni, kısa bir öneriyi, aynı adresleri
paylaşan diğer adları ve VirusTotal, AbuseIPDB (diğer kullanıcıların IP
raporları) ve urlscan (sitenin ekran görüntüsü; böylece siteyi açman gerekmez)
düğmelerini açar. Bunlar dış sitelerdir: ad ya da IP yalnızca tıkladığında
oraya gönderilir.

Her öğede, toplayıcı durumunun yanında özel olarak saklanan üç tek tıklık işaret
vardır: **Tanıyorum** öğeyi bundan sonra gizler (aynı ad ya da adres geri
geldiğinde de; *Tanıdık → Geri getir* geri alır), **Emin değilim** bir rozetle
tutar, **Şüpheli** öğeyi en üste sabitler ve bu sürümün toplayıcısıyla aynı ad
yeniden görüldüğünde masaüstü bildirimi gönderir (günde bir kez). Seçili bir
işarete yeniden tıklamak onu kaldırır. Tehdit listesindeki öğeler her zaman
görünür kalır. *İşaretsiz* filtresi karar verilecekleri gösterir. Aynı
bilgisayarın birkaç adresinden sorgulanan bir ad bir kez görünür. Gerçek IP'ler
kendi ekranında gösterilir; indirmeler takma adları korur. **Ayrıntılar** tam
teknik görünümü içerir. **Deneysel ML** aşağıda anlatılmıştır.

### Deneysel ML: Bu bilgisayar için yeni

Bu liste, bilgisayarın için **yeni** olan ve onu **sabit bir ritimle aramaya
devam ettiği** hedefleri gösterir (bir günde en az 4 bağlantı, ritim skoru
80/100 ya da üzeri); "eve haber veren" bir programın yaptığı gibi.

- **Bellek.** ThreatFusion, cihazlarının hangi siteleri (kayıtlı alan adı ya da
  DNS adı bilinmiyorsa IP) hangi günlerde kullandığını hatırlar. Bellek tek bir
  özel dosyadır, `<kurulum>/ml/baseline.json` (yalnızca sahibi okuyabilir) ve
  bilgisayardan asla çıkmaz. Sensörün tüm cihazlarını birlikte kapsar; böylece
  bir dizüstü bilgisayar ağ değiştirip adresi değişse de belleğini korur.
- **Öğrenme.** Bellekte 3 önceki günün trafiği olmadan hiçbir şey yeni sayılmaz.
  Bellek yalnızca uygulama açıkken büyür; uygulamanın çalışmadığı günler buna
  dahil değildir.
- **Ritim**, bağlantıların zamanlama ve boyut düzenliliğinden hesaplanan sabit
  bir skordur (sapmalara ve atlanan vuruşlara dayanıklıdır); eğitilmiş bir model
  değildir.
- **Site başına tek kart.** Aynı sitenin adresleri tek kartı paylaşır. Bir siteyi
  herhangi bir listede *Tanıyorum* olarak işaretlemek yeni kayıtlarını gizler;
  *Şüpheli* onları en üste sabitler.
- **Şimdiye kadar ölçülen:** herkese açık araştırma kayıtlarında ve projenin
  kendi trafiğinde normal bir cihaz için günde yaklaşık 0,5 kayıt (geliştirme
  düzeyi). Bakmak için bir sebeptir, zararlı yazılım hükmü değildir: araştırma
  verisindeki 6 komuta-kontrol hedefinden yalnızca 2'si ilk görüldüğünde
  yeniydi. Bağlayıcı test 7 günlük gerçek trafik çalışmasıdır.
- DNS sorgusu toplayıcının penceresinden önce yapılmış bir hedef yeni
  sayılabilir; ritim şartı bunların çoğunu eler.

### Deneysel ML: bu bilgisayarda eğitilen davranış modeli

*Bu bilgisayar için yeni* listesinin altında, bir rastgele orman (random forest)
modeli son günün her cihaz–hedef çiftini *nasıl* konuştuklarına göre puanlar:
ritim, boyutlar, süreler, başarısızlıklar, port ve adın ne kadar rastgele
göründüğü. Modelin eşiğinin üzerindeki çiftler sade gerekçeler ve bir ritim
grafiğiyle kart olarak görünür.

- **Öğrenme.** Uygulama günde yaklaşık bir kez toplayıcının en yeni 24 saatlik
  penceresindeki bağlantı gruplarını (yalnızca öznitelikleri)
  `<kurulum>/ml/local-days.json` dosyasında saklar (yalnızca sahibi okuyabilir).
  Bu şekilde 3 gün biriktikten sonra modeli burada, birkaç saniyede, uygulamayla
  gelen herkese açık zararlı ve normal kayıtların sayısal özniteliklerine ve
  normal kabul edilen senin günlerine dayanarak eğitir; her gün yeniden eğitir.
  O zamana kadar sekme kaç gün biriktiğini gösterir. Yalnızca uygulama
  toplayıcıyı okurken öğrenir.
- **Eşiği**, en yeni gününde ve herkese açık normal kayıtlarda günde en fazla bir
  grubu işaretleyen en düşük skordur.
- **Ölçülen** (aynı tarif, bir kez, hiç görmediği kayıtlarda): görmediği bir
  cihazda 7 zararlı aileden 5'i, görülmemiş zararlı kayıtlarının %56'sı, günde
  en fazla bir yanlış işaret; 2025–2026 zararlılarının ise yalnızca %27'si ve
  simüle beacon'ların %20'si. **Model değerlendirmesi** sayfası her testi
  listeler.
- **Sınırlar.** Bilgisayar ilk günlerinde zaten bulaşmışsa model bunu normal
  olarak öğrenir. Güncelleyiciler ve eşitleme araçları zararlı yazılıma benzer
  görünebilir; onları *Tanıyorum* olarak işaretle. Tehdit listesi kontrolleri ve
  Bakılacaklar bu modeli kullanmaz.

Yalnızca herkese açık kayıtlarla eğitilen modeller önceden ilan edilmiş
testlerini geçemedi ve kullanılmıyor. Geçmiş:
[ML değerlendirmesi](evidence/ML_DATASET.md) (İngilizce).

### Bir grubu incelemek

- Bir grubu seçince bağlantı başlangıçlarını zamana göre (UTC), Zeek bağlantı
  durumlarını ve bayt sayılarını görürsün; DNS için zamana göre sorguları ve
  yanıt türlerini.
- Cihazlar takma adlarla gösterilir (`Host 1`, `Device 1`). Gerçek adresleri
  kendi ekranında görmek için **Gözlenen cihaz IP'lerini yerelde göster;
  indirmeler takma adları korur** kutusunu işaretle.
- İndirmeler: görünen anlık görüntü JSON olarak; 1.000'den fazla grup varsa
  doğrulanmış tam bir JSON.gz. Her dışa aktarımı hassas veri olarak ele al.

### Beklenen etkinliği bildirmek

Bir bağlantının normal olduğunu doğruladıktan sonra, onu özel bir JSON
dosyasında tanımlayarak inceleme listesinden çıkarabilirsin (**Beklentiye uyan
etkinlikleri de göster** seçeneğiyle görünür kalır):

```bash
threatfusion-ai collect --input-dir … --expected-connections /ozel/expected.json
```

```json
{
  "schema_version": 1,
  "rules": [
    {
      "id": "checked-updater",
      "originator_ip": "192.0.2.1",
      "responder_ip": "198.51.100.1",
      "responder_port": 443,
      "protocol": "tcp",
      "valid_from": "2026-10-04T00:00:00Z",
      "valid_until": "2026-10-05T00:00:00Z",
      "max_connections": 100,
      "max_duration_seconds": 60,
      "max_originator_bytes": 100000,
      "max_responder_bytes": 1000000
    }
  ]
}
```

Kurallar tam IP'ler ve port, yalnızca TCP, en fazla 30 günlük bir geçerlilik
penceresi ve trafik sınırları gerektirir; en fazla 128 kural olabilir. CTI
eşleşmesi her zaman bildirimi geçersiz kılar. Bir bildirim, bağlantıyı hangi
programın yaptığını kanıtlayamaz. Kapsam eksikken (reddedilen ya da bekleyen
girdi, kapasite kaybı) bildirimler devre dışıdır. Bu kuralların kanıtı:
[beklenen bağlantı kontrolleri](evidence/EXPECTED_CONNECTIONS.md) (İngilizce).

### Büyük kayıt dosyaları

16 MiB'tan büyük dosyalar önce doğrulanmış özel parçalara bölünebilir:

```bash
threatfusion-ai prepare-logs --input /ozel/conn.log --output-dir ~/threatfusion-prepared/conn
threatfusion-ai collect --input-dir ~/threatfusion-prepared
```

`--quarantine-incomplete-dns`, sorgusu ya da türü olmayan DNS satırlarını tüm
dosyayı reddetmek yerine (özel olarak) kenara ayırır; sayfa kaç tane olduğunu
gösterir. Bu, 100.000 kayıtlık analiz penceresini büyütmez.

### Sınırlar

| Sınır | Değer |
| --- | --- |
| Tarama aralığı | 10 sn (1–3.600) |
| Kanıt penceresi | 24 sa (1–168) |
| Tutulan kayıt | Bağlantı + DNS kayıtları toplam 100.000 |
| DNS adı | 25.000 |
| Dosya / açılmış gzip | Her biri 16 MiB |
| Tarama başına | 8.192 dizin girdisi, 64 değişen dosya |
| Anlık görüntü | 64 MiB, JSON'da 1.000 grup, tabloda 500 satır |

Bir sınıra ulaşılması kapsam kaybı olarak gösterilir. Toplayıcı etkin CTI
göstergelerini bellekte tutar: yaklaşık 630.000 göstergeyle 0,5–0,9 GiB.

### Masaüstü bildirimi

Toplayıcı tehdit listesindeki bir eşleşmeye giden trafik gördüğünde, eşleşme
başına bir kez, uygulamada en son seçilen dilde bir masaüstü bildirimi gösterir
(Linux `notify-send`). Yalnızca tehdit listesi eşleşmeleri bildirim üretir,
davranış incelemeleri asla üretmez. Bildirim kilit ekranında görünebileceği için
yalnızca trafikte bir alan adı geçtiyse onu adlandırır ve asla IP göstermez.
Kapatmak için toplayıcıyı `--no-notify` ile başlat.

## Telemetriyi analiz et (yükleme)

Otomatik algılama şunları tanır: DNS sütunları olan CSV/TSV/TXT ve Excel, Zeek
`dns.log` ve `conn.log`, PCAP/PCAPNG (UDP 53 üzerinde düz DNS), Suricata EVE
JSON, Pi-hole FTL veritabanı, AdGuard Home sorgu kayıtları ve dnstop metni.
Yüklemeler bellekte işlenir; sınır 100 MB, 100.000 olay ve 25.000 farklı
hedeftir. Sonuçlar CTI kanıtını, davranış sinyallerini, cihaz başına
önceliklendirmeyi, ilgili etkinliği ve gizliliği koruyan dışa aktarımları
içerir.

## Hızlı sorgu

Bir URL, alan adı ya da IP yapıştır. ThreatFusion yalnızca yerel CTI önbelleğini
kontrol eder: sayfayı açmaz, adı çözümlemez ve hiçbir şey indirmez. Eşleşme
olmaması hedefin güvenli olduğu anlamına gelmez.

**Site yaşı (isteğe bağlı):** bir alan adı için **Site yaşını öğren** düğmesi,
alan adının resmî kayıt kuruluşuna (IANA üzerinden bulunan RDAP) ne zaman
kaydedildiğini sorar. Yalnızca kayıtlı alan adı gönderilir (`example.com`; tam
ana makine adı ya da URL asla gönderilmez) ve yalnızca düğmeye bastığında.
"Çok yeni" (30 gün ya da daha az) daha yakından bakmak için güçlü bir sebeptir,
ancak listelenmiş zararlı adların çoğu yeni değildir: projenin testinde yalnızca
yaklaşık 10'da 1'i 7 günlük ya da daha yeniydi
([kanıt](evidence/ML_DATASET.md), İngilizce). Eski bir site güvenli olduğunun
kanıtı değildir; yaş bir bağlamdır, hüküm değildir. Bazı ülke uzantılarının
herkese açık RDAP servisi yoktur. Herkesin ücretsiz ad açabildiği paylaşımlı bir
platformdaki adın (örneğin `name.web.app`) kendi kayıt girdisi yoktur; sonuç
bu durumda *Paylaşımlı platform* der ve platformu adlandırır. Bu, oltalama
sayfalarında sık görülen bir desendir.

Bir IP için Hızlı sorgu, yerel tablodan ağ sahibini gösterir. Hem alan adları
hem IP'ler dış arama düğmelerini (VirusTotal, AbuseIPDB, urlscan) alır. Sen
tıklamadıkça bu sitelere hiçbir şey gönderilmez.

## Modlar

- **Gerçek CTI (varsayılan):** kendi CTI önbelleğin; sözcüksel ML alan adı
  skoru kapalı. Yukarıdaki Deneysel ML sekmesi bu modda çalışır.
- **Demo:** arayüzü denemek için sentetik veri ve sentetik bir model. Sonuçları
  ölçüm değildir.

Sözcüksel alan adı modeli deneyseldir ve kapalıdır:
[ML değerlendirme geçmişi](evidence/ML_DATASET.md) (İngilizce).

## Örnek bir dosyayla denemek

Herhangi bir Zeek `dns.log` ya da `conn.log` dosyası **Telemetriyi analiz et**
sayfasına yüklenebilir. Gerçek zararlı yazılım olmadan tespitleri görmek için,
adları ya da IP'leri güncel CTI listelerinde bulunan birkaç kayıt satırı yaz
(Hızlı sorgu nelerin listelendiğini gösterir); onlara asla bağlanma. README
ekran görüntüleri bu yolla hazırlandı.

## ThreatFusion'ın yapmadıkları

Bir SIEM, EDR, IDS ya da zararlı yazılım tarayıcısı değildir. Paket yakalamaz,
trafiği çözmez, bağlantıları engellemez ve bir bağlantının arkasındaki programı
belirlemez. Gerçek zararlı yazılımdaki tespit oranları henüz ölçülmedi; bkz.
[kanıt dizini](README.tr.md#kanıtlar).
