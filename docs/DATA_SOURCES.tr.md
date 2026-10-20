# Veri kaynakları, atıf ve yeniden dağıtım notları

[English](DATA_SOURCES.md) • **Türkçe**

Bu depo, yerel inceleme için göstergeleri ve ağ/DNS telemetrisini bir araya
getirir. Tüm tehdit göstergelerini yalnızca etkisiz veri olarak ele al.

## Kodda kullanılan doğrulanmış kaynak uç noktaları

| Kaynak | Amaç | Depodaki uç nokta / referans |
| --- | --- | --- |
| ThreatFox (abuse.ch) | Zararlı IOC beslemesi toplama | `src/threatfusion/collectors/threatfox.py` (tam güncel dışa aktarım + yakın dönem API yedeği) |
| URLhaus (abuse.ch) | Zararlı yazılım dağıtım URL'si beslemesi toplama | `src/threatfusion/collectors/urlhaus.py` (tam veritabanı dökümü) |
| SGB (T.C. Siber Güvenlik Başkanlığı) | Zararlı adres beslemesi toplama | `src/threatfusion/collectors/sgb.py` (`SGB_API_URL`) |
| Tranco | Zararsız alan adı taban çizgisi girdisi; uygulama ilk 100.000'i haftada bir (anahtarsız) popüler site bağlamı olarak indirir, asla hüküm olarak kullanmaz | `src/threatfusion/collectors/tranco.py`, `src/threatfusion/popular_domains.py` |
| IANA RDAP bootstrap + kayıt kuruluşu RDAP sunucuları | Hızlı sorguda isteğe bağlı site yaşı; yalnızca analist düğmeye bastığında çalışır ve yalnızca kayıtlı alan adını gönderir | `src/threatfusion/domain_age.py` |
| iptoasn.com IP-ASN tablosu (PDDL) | Adresler için ağ sahibi ve kayıt ülkesi; haftalık, anahtarsız, yerelde aranır | `src/threatfusion/ip_owners.py` |
| CESNET / DomainRadar 2024 | Gerçek trafikten zararsız alan adı değerlendirme külliyatı | DOI `10.5281/zenodo.14332167`; `scripts/sample_cesnet_benign_domains.py` |
| CTU-SME-11 (Stratosphere Lab, Zenodo 7958259, CC BY 4.0) | Davranış modeli eğitimi ve testi: 11 cihazın 7 günlük (2023) etiketli Zeek akışları | Kayıtlar özel laboratuvarda kalır; türetilmiş sayısal bağlantı grubu öznitelikleri (adres, ad ya da zaman içermez) `src/threatfusion/models/behavior-public-features.npz` içinde gelir |
| Stratosphere MCFP kayıtları (CTU-Malware-Capture-Botnet, CTU-Normal) | Davranış modeli eğitimi ve testi: laboratuvarda bulaştırılmış ve normal makinelerin Zeek kayıtları (2011–2021) | Yukarıdaki gibi: kayıtlar özel; türetilmiş öznitelikler gönderilen pakette |
| Malware-Traffic-Analysis.net | Davranış modeli eğitimi (2023–2024) ve testi (2025–2026): bulaşma kayıtlarının Zeek kayıtları | Yukarıdaki gibi: kayıtlar özel; 2023–2024 türetilmiş öznitelikleri gönderilen pakette |
| Yerel ağ/DNS telemetrisi (kullanıcının sağladığı) | Çalışma zamanı analiz girdisi | CSV/TSV/TXT, Excel, Zeek, PCAP/PCAPNG, Suricata EVE, Pi-hole, AdGuard ve dnstop içe aktarma modülleri |

## Atıf gereklilikleri

- Toplu bulguları sunarken kaynak atfını koru.
- ThreatFusion AI'ın üçüncü taraf besleme içeriğinin sahibi olduğunu ima etme.
- Mümkün olduğunda kanıt/rapor çıktısında beslemeye özgü kaynak adlarını koru.

## Yeniden dağıtım ve lisans durumu

Güncel resmî kaynak belgelerinden doğrulanmıştır:

- Kod besleme uç noktalarını ve içe aktarma mantığını içerir; canlı ThreatFox,
  URLhaus, SGB ya da Tranco veri setlerinin bir kopyasını **içermez**.
- ThreatFox ve URLhaus, abuse.ch Kullanım Koşulları ve Adil Kullanım İlkelerine
  tabi abuse.ch platformlarıdır. Topluluk API'leri kimliği doğrulanmış, kâr
  amacı gütmeyen/adil kullanım erişimi içindir; ticari ya da kâr amaçlı kullanım
  bir Spamhaus aboneliği gerektirebilir. Bkz.:
  - https://abuse.ch/terms-of-use/
  - https://threatfox.abuse.ch/api/
  - https://urlhaus.abuse.ch/api/
- PhishTank 2026-10-09'da kaldırıldı (DEC-089). Artık yeni uygulama anahtarı
  vermiyor ve 2026-10-07'den beri anahtarsız herkese açık URL'si, bir görselle
  HTTP 404 yanıtı veren bir `cdn.phishtank.com` yoluna yönlendiriyordu (HTTP
  302). Toplayıcısı, anahtar alanı ve durum kartı kaldırıldı; bir sonraki
  güncelleme eski yerel önbelleklerdeki PhishTank satırlarını siler.
- SGB API belgesi, zararlı adres istihbaratının güvenlik ürünlerine/sistemlerine
  otomatik entegrasyonunu açıkça tarif eder; ancak bu depo o ifadeyi geniş bir
  yeniden dağıtım lisansı olarak kabul etmez. Bkz.:
  https://siberguvenlik.gov.tr/api/
- Tranco, lisansları birbirinden farklı birden çok kaynaktan derlenen,
  yeniden üretilebilir indirilebilir sıralamalar yayımlar. Bu nedenle
  ThreatFusion birleşik sıralamayı yeniden dağıtılacak bir depo varlığı olarak
  ele almaz. Bkz.: https://tranco-list.eu/
- CESNET/DomainRadar 2024 veri seti CC BY 4.0 lisansıyla yayımlanmıştır.
  ThreatFusion yalnızca atfı ve yerelde örneklenen değerlendirme girdilerini
  saklar; depoya hiçbir CESNET külliyatı eklenmez.

Demo ve yayın politikası:

- ham üçüncü taraf besleme dökümlerini ya da geliştiricinin canlı CTI önbelleğini
  yayımlama
- yerel demo modu önbelleğini `src/threatfusion/demo_cti.py` ile oluşturur;
  yalnızca belgelendirme için ayrılmış değerler içerir, ThreatFox, URLhaus, SGB,
  Tranco ya da CESNET kayıtları içermez
- yerelde indirilen üçüncü taraf verilerden türetilen sonuçları sunarken kaynak
  atfını koru

Bu, olası her yeniden dağıtım senaryosu hakkında hukuki bir sonuç değil,
ihtiyatlı bir yayın sınırıdır.

## Telemetri gizliliği notları

- Kullanıcının yüklediği ağ/DNS telemetrisi varsayılan olarak yerelde/bellekte
  analiz edilir.
- Herkese açık yayın hazırlığı özel telemetri dışa aktarımlarını, yerel analist
  geçmişini ya da gizli bilgileri içermemelidir.

## Yerel CTI önbelleğinin yaşam döngüsü

Başarılı bir güncelleme, en son kaynak anlık görüntüsünden kaybolan göstergeleri
artık silmez. Önbellek onları etkin olmayan yaşam döngüsü geçmişi olarak tutar
ve bir göstergenin ilk ne zaman önbelleğe alındığını ve başarılı bir
güncellemede en son ne zaman görüldüğünü kaydeder. Çalışma zamanı eşleştirmesi
varsayılan olarak yalnızca etkin göstergeleri yükler.

Bu yaşam döngüsü durumu ThreatFusion'ın yerel önbellek gözlemlerini anlatır.
Bir beslemenin kendi IOC `first_seen` / `last_seen` meta verisiyle
karıştırılmamalıdır.

SGB toplama, çağıranın belirlediği en fazla sayfa sayısıyla sınırlıdır ve API
tüm satırların toplandığını bildirdiğinde ya da boş bir sayfa döndürdüğünde daha
erken durur. Zamanlanmış bir güncelleme, yapılandırılan sayfa sınırına kaynağın
sonundan önce ulaşılırsa önceki SGB anlık görüntüsünü değiştirmeyi reddeder.

ThreatFox güncellemeleri yalnızca 1-7 günlük yakın dönem IOC API penceresini
değil, tam güncel dışa aktarımı kullanır. URLhaus güncellemeleri tam zararlı URL
dökümünü kullanır. Bu, Hızlı sorgu kapsamının yalnızca yeni eklenen IOC'lere
küçülmesini önler.

Hızlı sorgu, tüm etkin CTI veri setini Python'a yüklemez. SQLite önbelleği
normalleştirilmiş arama anahtarlarını ve dizinlenmiş URL ana makine adlarını
saklar; böylece tek bir URL/alan adı sorgusu yalnızca ilgili aday göstergeleri
getirir.

## README ekran görüntülerinde gösterilen göstergeler

README ekran görüntüleri, geliştiricinin kendi önbelleğinden üç herkese açık
göstergeyi (bir ThreatFox AsyncRAT komuta IP'si, bir ThreatFox RemusStealer
komuta alan adı ve bir SGB oltalama alan adı) hazırlanmış Zeek kayıtlarında
gösterir. Kaynakları belirtilerek örnek amacıyla gösterilmişlerdir; liste
içeriği yeniden dağıtılmamış ve onlara hiçbir trafik gönderilmemiştir.

## CESNET zararsız külliyat atfı

Uzun kuyruk zararsız değerlendirme yardımcısı 2024 DomainRadar veri setine
dayanır:

- Hranický ve diğerleri, *A Dataset of Information (DNS, IP, WHOIS/RDAP, TLS, GeoIP) for a Large Corpus of Benign, Phishing, and Malware Domain Names 2024*
- DOI: `10.5281/zenodo.14332167`
- alt küme: `benign_cesnet.json`
- yayımlanan lisans: CC BY 4.0

CESNET alt kümesi gerçek akademik ağ trafiğinden türetilmiş ve veri setinin
yazarlarınca filtrelenmiştir. ThreatFusion onu yalnızca zararsız etiketli bir
alan adı metni değerlendirme külliyatı olarak kullanır. Ham DNS telemetrisi ya da
gerçek bir sorgu sıklığı dağılımı olarak sunulmaz.
