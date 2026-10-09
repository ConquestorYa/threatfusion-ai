# Kalan manuel testler (P0)

Bu dosyada yalnızca **henüz yapılmamış** testler var. Tamamlananlar kayıt için
[RELEASE_HANDOFF.md](RELEASE_HANDOFF.md) içine taşındı.

**Nasıl işaretlenir:** Her maddenin başındaki `[ ]` içine `x` yaz: `[x]`.
Bir şey beklenenden farklıysa maddenin altına kısa bir not yaz:

> Ne yaptım: … / Ne bekledim: … / Ne oldu: … (ekran görüntüsü varsa çok iyi)

Bu dosyayı **bilgisayarındaki kopyada** düzenle:
`~/Work/threatfusion-ai/docs/MANUAL_ACCEPTANCE_TR.md`. GitHub sitesinde
düzenleme. İstersen sonuçları doğrudan sohbete de yazabilirsin.

Toplam süre: yaklaşık **40–50 dakika**. Bölümleri ayrı günlerde de yapabilirsin.

---

## Bölüm A — En son sürüme güncelle (5 dk)

**Amaç:** Testleri son düzeltmelerle yapmak.
**Gerekenler:** İnternet. API anahtarı gerekmez.

1. Terminalde uygulamayı durdur:

   ```bash
   threatfusion-ai stop
   ```

2. [README.tr.md](../README.tr.md) içindeki **"Linux — tek komutla local
   kurulum"** komutunu aynen tekrar çalıştır. Silip yeniden kurmana gerek yok;
   verilerin ve kayıtlı anahtarların korunur.
3. Kurulum bitince uygulama tarayıcıda kendiliğinden açılır. Açılmazsa
   terminalde `threatfusion-ai` yaz.
4. Kurulu sürümü kontrol et:

   ```bash
   grep -o 'releases/[0-9a-f]\{7\}' ~/.local/share/threatfusion-ai/installation.json
   ```

- [x] Çıktı `releases/df75d61` (veya Claude'un son mesajında söylediği daha
      yeni bir numara).
      — Kullanıcı (sohbet): `releases/1364e07`.

> Not: Adres her zaman `http://127.0.0.1:…` veya `http://localhost:…` olmalı.
> Başka bir adresle açarsan güvenlik gereği boş sayfa görürsün.

---

## Bölüm B — CTI güncellemesi sırasında uygulamayı kullanmak (10 dk)

**Amaç:** Büyük bir güncelleme sürerken uygulamanın hata vermeden çalışmaya
devam ettiğini görmek. Önceki denemede burada "database is locked" hatası
çıkmıştı; düzeltildi.

**Gerekenler:**
- İnternet açık.
- **API anahtarı:** Daha önce ThreatFox ve URLhaus anahtarlarını
  **kaydettin**; uygulama onları otomatik kullanır, tekrar girmen gerekmez.
  Yan panelde "Kayıtlı anahtarlar: ThreatFox, URLhaus" (İngilizcede "Saved
  keys") yazısını görmelisin. Görmüyorsan anahtarlarını aynı panelden tekrar gir ve
  "Anahtarları bu bilgisayara kaydet" kutusunu işaretleyip **Anahtarları
  uygula**'ya bas. SGB ve PhishTank anahtar istemez.
- Uygulamayı başlattığın **terminal penceresini açık tut**; hata çıkarsa orada
  görünür.

**Adımlar:**

1. Sol yan çubuktaki **Sayfalar** listesinden **Kurulum ve CTI güncellemeleri** sayfasını aç.
2. **Kaynaklar güncel olsa da yeniden indir** kutusunu işaretle.
3. **CTI verilerini şimdi güncelle** düğmesine bas.
4. Güncelleme sürerken (birkaç dakika):
   - üstteki ilerleme çubuğunu izle,
   - başka bir sayfaya geç ve geri dön,
   - yan çubuktan dili değiştir,
   - ana sayfada **Hızlı sorgu** alanına `wikipedia.org` yazıp **Kontrol et**'e bas.
5. Bitmesini bekle ve süreyi not et.

**Beklenen:**

- [x] Güncelleme boyunca web sayfasında da terminalde de **hiç hata** çıkmadı
      ("Traceback" veya "database is locked" yazısı yok).
- [x] Hızlı sorgu güncelleme sürerken de sonuç verdi.
      — Kullanıcı (sohbet): sayfa, dil ve tema değiştirildi; hızlı sorgu
      yapıldı; hiçbirinde sorun yok, terminalde hata yok.
- [x] Bitince "CTI güncellemesi tamamlandı: … kaynak indirildi" mesajı çıktı ve
      düğme yeniden tıklanabilir oldu.
- [x] PhishTank notu — kullanıcı (sohbet): görünmedi. Sebep: not panelin en
      altındaydı. **Düzeltildi**, güncelleme (Bölüm A) sonrası tekrar bak:
  - [x] **CTI verilerini şimdi güncelle** düğmesinin hemen altında, "Son deneme"
        satırının altında **mavi** not var: "PhishTank: anahtarsız public kaynak
        şu an kaynağın kendisinden alınamıyor; senin tarafında düzeltilecek bir
        şey yok…". (Güncelleme yapmana gerek yok; paneli açman yeterli.)
  - [x] Sol yan çubuktaki **PhishTank · Doğrulanmış ve Çevrimiçi** kartında
        "Güncelleme zamanı bilinmiyor" yerine "Anahtarsız public kaynak şu an
        kaynağın kendisinden alınamıyor" yazıyor. (PhishTank'ın kendi hizmeti
        çalışmıyor; kayıt gelmemesi beklenen durum.)
      — Kullanıcı (sohbet, `532609f`): Bölüm B'deki her şey tamam.
- [x] Panelde "Kaynaklar güncel; sonraki indirme yaklaşık … saat sonra" yazıyor.
      — Kullanıcı (sohbet): "yaklaşık 6.0 saat sonra".
- [x] Güncelleme yaklaşık **2 dakika** sürdü (kullanıcı, sohbet).

---

## Bölüm C — İnternet yokken güncelleme (5 dk)

**Amaç:** İnternet kesikken uygulamanın anlaşılır bir mesaj verdiğini ve eski
verileri silmediğini görmek.
**Gerekenler:** Bölüm B bitmiş olmalı. API anahtarı gerekmez (kayıtlı olanlar
kullanılır).

1. Yan panelde kaynakların **kayıt sayılarını** not et (ör. SGB 488.915).
2. Wi-Fi'ı (veya kablolu interneti) kapat.
3. **Kaynaklar güncel olsa da yeniden indir** kutusunu işaretle ve **CTI
   verilerini şimdi güncelle**'ye bas. (Kutu yalnızca o güncelleme için
   geçerlidir; güncelleme başlayınca temizlenir.)
4. Birkaç saniye bekle.

**Beklenen:**

- [x] "Hiçbir CTI kaynağına ulaşılamadı. İnternet bağlantını kontrol et; mevcut
      veriler korunuyor" mesajı çıktı.
- [x] Düğme yeniden tıklanabilir oldu.
- [x] Kayıt sayıları **değişmedi** (1. adımdakiyle aynı). — Kullanıcı (sohbet):
      üç madde de tamam.

5. Wi-Fi'ı aç. **"Kaynaklar güncel olsa da yeniden indir" kutusunu yeniden
   işaretle** (kutu her güncelleme başlayınca kendiliğinden temizlenir; tek
   seferliktir) ve **CTI verilerini şimdi güncelle**'ye bas.

- [x] Güncelleme bu kez gerçekten indirdi: "CTI güncellemesi tamamlandı: 3
      kaynak indirildi" mesajı çıktı.
  - Kullanıcı (sohbet): ilk denemede kutu temizlendiği için "CTI is already up
    to date" çıktı; bu bir hata değil (kaynaklar zaten günceldi), ama internetin
    geri geldiğini göstermiyor. Kutuyu yeniden işaretleyip tekrar dene.

---

## Bölüm D — Hızlı sorgu (3 dk)

**Amaç:** Tek bir alan adı/IP kontrolünün anlaşılır olduğunu görmek.
**Gerekenler:** Hiçbir şey. Sorgular internete çıkmaz, siteleri ziyaret etmez;
yalnızca bilgisayarındaki CTI verisine bakar.

Ana sayfadaki **URL, domain veya IP** (İngilizce: **URL, domain or IP**) kutusuna
yaz ve **Kontrol et** (**Check**)'e bas. Arayüz İngilizceyse mesajlar da
İngilizce çıkar; bu normal.

- [x] `wikipedia.org` → eşleşme yok; ayrıca bunun "kesin güvenli" anlamına
      gelmediğini söylüyor. — Kullanıcı (sohbet): "No threat signal found".
      Uyarı aşağıdaki **Threat intelligence evidence** bölümünde: "No CTI match
      found … This does not guarantee that the destination is safe."
- [x] `8.8.8.8` → sonuç anlaşılır. — Kullanıcı (sohbet): "No threat signal found".
- [x] `abc def` → uygulama çökmüyor; açıklayıcı bir hata çıkıyor. — Kullanıcı
      (sohbet, İngilizce arayüz): "Lookup input could not be analyzed: internet
      domain must contain at least two labels". Türkçe arayüzde: "Girdi analiz
      edilemedi: alan adı en az iki bölümden oluşmalı…".

---

## Bölüm E — Zeek log toplama (10 dk)

**Amaç:** Uygulamanın ağ kayıtlarını (Zeek logları) otomatik toplayıp hangi
cihaz/hedefin neden incelenmesi gerektiğini gösterdiğini görmek.
**Gerekenler:** Uygulama açık. İnternet veya API anahtarı gerekmez. Lab'daki
**sentetik** (yapay) örnek veri kullanılır; gerçek trafik değildir.

1. **Yeni bir terminal** aç (uygulamanınki açık kalsın) ve şunu çalıştır:

   ```bash
   threatfusion-ai collect --input-dir /home/yahya/Work/threatfusion-lab/analyst-guidance-v1/traffic/development/zeek
   ```

   Komut kapanmaz; 10 saniyede bir tarama yapar ve her taramada bir satır
   yazar. Bu normal.

- [x] İlk satırda `"new_records": 818` ve `"review_groups": 8` var; sonraki
      satırlarda `"new_records": 0`. — Kullanıcı (sohbet): aynen böyle
      (`"dns_review_groups": 1` dahil).

2. Tarayıcıda sol yan çubuktaki **Sayfalar** listesinden **Toplanan bağlantılar**'a
   tıkla. Sayfanın üst başlığı **Toplanan bağlantılar** (İngilizce: **Collected
   connections**) olmalı.
   - Kullanıcı (sohbet): sayfa açılıyordu ama başlık büyük kartların altında
     kaldığı için değiştiği belli olmuyordu. **Düzeltildi:** ikincil sayfalar
     artık başlıkla başlıyor; yan çubukta aktif sayfa vurgulanıyor.

- [x] Tabloda **8** inceleme grubu var. Cihazlar gerçek IP yerine `Sistem 001`
      gibi takma adlarla görünüyor.
- [x] Tablonun altından bir grup seçince zaman çizelgesi ve **İnceleme
      rehberi** (neden incelenmeli, sonra neye bakılmalı) görünüyor ve
      anlaşılır.
- [x] Aynı sayfanın aşağısındaki **Toplanan DNS gözlemleri** bölümünde **1**
      inceleme grubu var. **İnceleme önceliği olmayan gözlemleri de göster**
      kutusunu işaretleyince diğer DNS kayıtları da görünüyor.

3. Toplama terminalinde **Ctrl+C**'ye bas (toplayıcı durur), sonra aynı komutu
   tekrar çalıştır.

- [x] Yeni çalıştırmada `"new_records": 0` yazıyor; aynı kayıtlar ikinci kez
      eklenmedi.
      — Kullanıcı (sohbet + ekran görüntüsü): 8 grup, "Sistem" takma adları,
      İnceleme rehberi, DNS gözlemleri kutusu ve tekrar çalıştırmada
      `"new_records": 0` doğrulandı.

4. İşin bitince toplama terminalinde tekrar **Ctrl+C**'ye bas.

> Önemli: Bu testte başka bir klasör verme. `reserved` adlı klasörleri açma;
> onlar ileride yapılacak ölçümler için ayrıldı.

---

## Bölüm F — Rapor indirme ve gizlilik (5 dk)

**Amaç:** İndirilen raporlarda gerçek IP adreslerinin bulunmadığını görmek.
**Gerekenler:** Bölüm E yapılmış olmalı. **Toplanan bağlantılar** sayfasında ol.

1. **Toplanan bağlantıların JSON raporunu indir** düğmesine bas. (Dosya
   `~/Downloads/threatfusion_collected_connections.json` olarak iner.)
2. İnen dosyayı bir metin düzenleyiciyle aç (ör. çift tıkla veya
   `cat ~/Downloads/<dosya_adı>.json`).

- [x] Dosyada cihazlar `Host 002`, `Device 006` gibi takma adlarla geçiyor;
      `192.168…` gibi gerçek IP adresi yok. — Kullanıcı (sohbet) + Claude'un
      taraması: 0 IPv4, 0 IPv6; yalnızca `Host …` / `Device …` takma adları.
      (Dosyada 23 bağlantı grubu var; ekrandaki tablo varsayılan olarak yalnızca
      8 inceleme grubunu gösterir.)

3. Sayfada **Gözlenen cihaz IP'lerini yerelde göster; indirmeler takma adları
   korur** kutusunu işaretle.

- [x] Tabloda artık gerçek IP adresleri görünüyor (yalnızca senin ekranında).
- [x] Raporu tekrar indirip açtım: dosyada yine yalnızca takma adlar var.
      — Kullanıcı (sohbet) + Claude'un taraması: `threatfusion_collected_connections
      (1).json` içinde 0 IPv4, 0 IPv6; yalnızca takma adlar.

---

## Bölüm G — Genel izlenim (serbest)

- [ ] Bir analist gözüyle: "Hangi cihaza / hedefe neden bakmalıyım?" sorusuna
      cevap bulabildim. Bulamadıysam nerede takıldığımı yazdım.
- [ ] Anlamsız, kafa karıştırıcı veya çevrilmemiş Türkçe metin gördüm mü?
      Gördüysem nerede olduğunu yazdım.
- Ekledikleri / kafama takılanlar:
  - Kullanıcı (sohbet, 2026-10-09): "Genel olarak arayüz ile ilgili çok fazla
    şikayetim var… sitenin yapay zekadan yapıldığı çok belli oluyor." Arayüzün
    baştan, daha profesyonel bir görünümle yeniden tasarlanmasını istiyor.
    Ayrıntılı şikâyet listesi bekleniyor.


---

## Bölüm H — Yeni arayüz (yeniden tasarım sonrası, ~15 dk)

**Amaç:** Yeni görünümün profesyonel, okunaklı ve tutarlı olduğunu görmek.
Arka plan özellikleri değişmedi; yalnızca görünüm ve sayfa düzeni değişti.
**Gerekenler:** Bölüm A'daki gibi güncelle. İnternet veya API anahtarı gerekmez.

1. Uygulamayı aç. Üst sağda **Türkçe / English** ve **Koyu / Açık** (Dark /
   Light) düğmeleri, solda **Sayfalar** listesi var: Hızlı sorgu, Telemetriyi
   analiz et, Toplanan bağlantılar, Model değerlendirme, Kurulum ve CTI
   güncellemeleri. Bulunduğun sayfa vurgulu görünür.
2. **Açık**'a bas: sayfa kendiliğinden yenilenip açık temaya geçer. Sonra
   **Koyu**'ya bas. (Tema değişince sayfa yenilenir; açık sonuçlar kapanır, bu
   beklenen davranış.)
3. Her iki temada soldaki listeden tüm sayfaları gez; **Hızlı sorgu**'da bir
   sorgu yap (ör. `wikipedia.org`). API anahtarları, CTI güncelleme ve otomatik
   güncelleme artık **Kurulum ve CTI güncellemeleri** sayfasında. Dili de
   değiştirip birkaç yere bak.

- [ ] Yazı tipi değişti (IBM Plex); logo, renkler ve çizgiler sade ve profesyonel görünüyor;
      "yapay zekâ yapmış" hissi yok ya da belirgin şekilde azaldı.
- [ ] Açık temada her şey açık (tablolar, kutular, yan çubuk dahil); koyu
      temada her şey koyu. Yarısı açık yarısı koyu bir alan yok.
- [ ] Hiçbir yerde okunmayan, soluk kalan veya renk uyumsuz yazı yok.
- [ ] Tema değiştirme düğmesi her iki yönde çalışıyor.
- [ ] Soldaki **Sayfalar** listesiyle her sayfaya tek tıkla ulaşabiliyorum;
      her sayfanın başlığı en üstte, sayfanın değiştiği hemen belli oluyor.
- [ ] Sol paneldeki **Durum** bölümü (CTI kaynakları ve güncellikleri) anlaşılır;
      kaynak ayrıntıları Kurulum sayfasındaki tabloda.
- Kullanıcı (sohbet, `31fbf7f` sonrası): "şuan arayüz çok daha iyi." Maddelerin
  tek tek işaretlenmesi bekleniyor.
- Beğenmediğin yerleri ekran görüntüsüyle yaz (ör. "yan çubuk çok kalabalık",
  "logo olmamış", "bu renk koyu").
---

## Sonuç

- Tarih:
- Kurulu sürüm (Bölüm A'daki çıktı):
- Bulunan sorunlar:
- Genel değerlendirme (geçti / sorunlu):
