# Zeek sensör kurulumu

[English](ZEEK_SETUP.md) • **Türkçe**

ThreatFusion **tamamlanmış Zeek kayıtlarını** analiz eder; paketleri kendisi
yakalamaz. Bu kılavuz, kayıtlarını toplayıcının okuyabileceği küçük bir Zeek
sensörü kurar. Aşağıdaki tarif (Docker, sürümü sabitlenmiş Zeek 8.0.6, tek ağ
arayüzü) projenin kendi gerçek trafik testinde kullanılandır; *henüz
doğrulanmadı* diye işaretlenen seçenekler uçtan uca denenmedi.

## 1. Sensörün neyi görebileceğine karar ver

Zeek yalnızca dinlediği arayüzden geçen paketleri görür.

| Yerleşim | Görünenler | Gerekenler | Durum |
| --- | --- | --- | --- |
| Bu bilgisayarın kendi arayüzü | Bu bilgisayarın trafiği ve aynı ağdaki diğer cihazların yerel yayın (broadcast/multicast) duyuruları (aşağıda filtrelenir) | Ek bir şey gerekmez | Doğrulandı |
| Bu bilgisayar, kablolu bir PC için ağ geçidi | O PC'nin paylaşılan Ethernet portundaki trafiği | Ethernet kablosu, NetworkManager bağlantı paylaşımı | Henüz doğrulanmadı |
| Bu bilgisayarın Wi-Fi erişim noktası (hotspot) | Erişim noktasına bağladığın cihazlar | İstemci moduyla birlikte AP modunu destekleyen bir Wi-Fi kartı | Henüz doğrulanmadı |
| Tüm ağ | Her cihaz | Yönlendirici/switch port yansıtma (port mirroring) ya da OpenWrt yönlendirici | Henüz doğrulanmadı |

Yalnızca sahibi olduğun ya da izlemene izin verilen ağları ve cihazları izle.
Başkalarının cihazları görünüyorsa önce onlardan izin al.

## 2. Zeek'i çalıştır

Gerekenler: Docker ve paket yakalama yetkisi. `docker` grubuna üye olmak o
makinede root yetkisine eşdeğerdir.

Arayüz adını bul (örneğin Wi-Fi için `wlp63s0`, Ethernet için `enp64s0`):

```bash
ip -br link
```

Özel bir klasör ve **yalnızca bağlantı ve DNS kayıtlarını** sekmeyle ayrılmış
metin olarak yazan, saatte bir döndürülen bir Zeek betiği oluştur:

```bash
mkdir -m 700 -p ~/zeek-sensor/logs
cat > ~/zeek-sensor/threatfusion.zeek <<'EOF'
@load base/protocols/conn
@load base/protocols/dns
redef LogAscii::use_json = F;
redef Log::default_rotation_interval = 1 hr;
EOF
```

Zeek'i başlat (`wlp63s0` yerine kendi arayüzünü yaz):

```bash
docker run -d --name tf-zeek --restart unless-stopped --network host \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  -v ~/zeek-sensor:/w -w /w/logs \
  zeek/zeek@sha256:f0582e7ba4a81fb55145fc03eddb6aefe70dbceee1d47df69f9bb781be952f6d \
  zeek -b -C -i wlp63s0 /w/threatfusion.zeek \
  -f 'not ether multicast and not (udp port 137 or udp port 138 or udp port 1900 or udp port 3702 or udp port 5353 or udp port 5355)'
```

- `-b` yalnızca yukarıdaki iki betiği yükler: HTTP, TLS, sertifika ya da dosya
  kaydı yoktur.
- `-f …` yerel ağ keşif trafiğini (broadcast/multicast çerçeveleri, NetBIOS,
  SSDP, WS-Discovery, mDNS, LLMNR) atar. Kampüs Wi-Fi'ı gibi kalabalık,
  paylaşımlı bir ağda yüzlerce cihaz kendini bu şekilde duyurur; projenin kendi
  testinde tek bir öğleden sonra bir milyondan fazla böyle DNS kayıt satırı
  üretti, saatlik kayıtlar içe aktarılamayacak kadar büyüdü ve toplayıcının
  penceresi doldu. Bu trafiğin hiçbiri yerel ağdan çıkmaz. Toplayıcı, filtre
  olmadan kurulmuş sensörler için bu satırları da atlar
  (`skipped_local_discovery_rows`), ama dosyaları küçük tutan yalnızca Zeek'in
  filtresidir.
- `-C` sağlama toplamlarını yok sayar; kendi giden paketlerini yakalayan bir
  bilgisayar genellikle geçersiz sağlama toplamları görür, çünkü ağ kartı
  bunları daha sonra hesaplar.
- Saatlik döndürme önemlidir. Toplayıcı bir kaydı ancak Zeek onu kapattıktan
  sonra içe aktarır (son satır `#close` ile başlar). Döndürme olmazsa Zeek tek
  bir dosyaya yazmaya devam eder ve Zeek durana kadar hiçbir şey içe aktarılmaz.

Zeek'i `docker stop tf-zeek` ile durdur; açık dosyalarını kapatıp döndürür.

## 3. Kayıtları kontrol et

İlk tam saatten sonra klasörde döndürülmüş dosyalar olur:

```bash
ls ~/zeek-sensor/logs          # conn.2026-10-10-02-00-00.log, dns.….log, conn.log (hâlâ açık)
tail -n 1 ~/zeek-sensor/logs/conn.2026-*.log | head   # kapanmış her dosya #close ile biter
```

Açık `conn.log` / `dns.log` dosyaları döndürülene kadar atlanır.

## 4. ThreatFusion'ı bağla

```bash
threatfusion-ai collect --input-dir ~/zeek-sensor/logs
```

Uygulamayı aç ve **Toplanan bağlantılar** sayfasını seç. Ayrıntılar
[kullanım kılavuzunda](USER_GUIDE.tr.md#toplayıcı).

## Neler kaydedilir, gizlilik

- `conn.log`: hangi cihazın hangi IP ve porta, ne zaman, ne kadar süreyle ve kaç
  bayt ile bağlandığı. İçerik yok.
- `dns.log`: hangi adların sorgulandığı ve yanıtları. Bu, pratikte ziyaret
  ettiğin sitelerin listesidir (sayfalar değil, adlar).
- Şifreli içerik (HTTPS) görünmez: parolalar, sayfa adresleri ve form içerikleri
  asla kaydedilmez.
- Kayıtlar özel klasöründe kalır. Onları commit etme, yükleme ya da paylaşma.

## Şifreli DNS adları gizler

Sistem ya da tarayıcı DNS'i şifreli gönderiyorsa (DNS-over-TLS ya da
DNS-over-HTTPS), `dns.log` neredeyse boş kalır ve DNS listesinde gösterilecek bir
şey olmaz. Bağlantı analizi yine çalışır. Sistemin DNS çözümleyicisini kontrol
etmek için:

```bash
resolvectl status | grep -E "Current DNS|DNSOverTLS"
```

`DNSOverTLS=yes` ya da destekleyen bir çözümleyiciyle `opportunistic`, sistem
DNS'inin şifreli olduğu anlamına gelir. Bunu değiştirmek bir gizlilik
ödünleşimidir; ThreatFusion bunu gerektirmez.

## Dizüstü bilgisayarlar: uyku boşluk yaratır

Uyuyan ya da kapalı bir sensör hiçbir şey kaydetmez. Boş saatler kapsam
boşluklarıdır, sessiz bir ağın kanıtı değildir. Kayıt sürerken dizüstü
bilgisayarı uyanık tutmak için:

```bash
systemd-inhibit --what=sleep:idle --why="Zeek capture" sleep infinity
```

Kapağı kapatmak, ayarlara bağlı olarak makineyi yine de uykuya alabilir.

## Sensörü kaldırma

```bash
docker rm -f tf-zeek          # kapsayıcıyı durdur ve kaldır
docker rmi zeek/zeek@sha256:f0582e7ba4a81fb55145fc03eddb6aefe70dbceee1d47df69f9bb781be952f6d
rm -rf ~/zeek-sensor          # betiği ve kaydedilen tüm kayıtları siler
```

Kayıtlar ağ etkinliğinin bir dökümüdür; artık ihtiyacın olmadığında sil.
