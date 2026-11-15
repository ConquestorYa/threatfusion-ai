# Pazartesi demosu: kontrol listesi (React çalışma alanı)

Branch: `feat/react-workspace` (PR #185, taslak; `main`'e birleştirilmedi).
Demonun tamamı yeni arayüzde yapılır; Streamlit yalnızca yedek.

**Güvenli hale dönüş (tek komut):** son denenmiş sağlam sürüm `demo-stable`
etiketidir (dört ekran, CI yeşil; Telemetri analizi o sürümde Streamlit'te):

```bash
git switch --detach demo-stable && (cd web && npm ci && npm run build)
```

Geri gelmek için: `git switch feat/react-workspace && (cd web && npm ci && npm run build)`.
Demo yalnızca **sentetik veriyle** yapılır: dokümantasyon IP aralıkları
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), `.test` alan adları ve
"Synthetic demo" adlı sahte bir CTI kaynağı. Gerçek ağ verisi, gerçek IP ya da
gerçek API anahtarı ekrana gelmez. Her şey yalnızca `127.0.0.1`'de çalışır.

## 1. Demodan önce (bir kez, ~10 dk)

- [ ] `git fetch && git switch feat/react-workspace && git pull`
- [ ] Python bağımlılıkları: `.venv/bin/pip install -r requirements.txt`
      (`fastapi` dahil; yeni ortamda `pip install --no-deps -e .` da gerekir)
- [ ] Sayfayı derle: `cd web && npm ci && npm run build && cd ..`
      (Node 22 gerekir: `nvm use 22`)
- [ ] Hızlı doğrulama (isteğe bağlı, ~3 dk):
      `.venv/bin/ruff check . && .venv/bin/python -m pytest -q` ve
      `cd web && npm test && npm run test:e2e`
- [ ] Tarayıcıda bu sitenin kayıtlı tercihlerini temizle (ya da gizli pencere
      kullan): temiz açılış **koyu tema + Türkçe** gelmeli.

## 2. Demoyu başlat (demodan hemen önce)

- [ ] `scripts/demo_web.sh` — sentetik yönetilen kurulumu yaratır, toplayıcıyı
      (10 sn'de bir), React API'sini ve Streamlit'i başlatır.
- [ ] React: http://127.0.0.1:8600 · Streamlit: http://127.0.0.1:8501
- [ ] Sunucular yalnızca loopback'te mi?
      `ss -ltnp | grep -E ':8600|:8501'` → yalnızca `127.0.0.1`.
- [ ] Bitince **Ctrl+C**: üç süreç durur, geçici klasör silinir.

Portlar doluysa: `API_PORT=8610 STREAMLIT_PORT=8511 scripts/demo_web.sh`.

## 3. Kısa senaryo (5 dakika)

Hepsi koyu tema ve Türkçe, yalnızca sentetik veriyle.

**1) Bakılacaklar (~1,5 dk)**
- [ ] `198.51.100.20` satırının okuna bas → açıklama açılır.
- [ ] Söyle: *"Bu ekran ağdaki cihazların neyle konuştuğunu toplayıcıdan
      okuyor ve bakılması gerekenleri öne çıkarıyor. Her satır nedenini düz
      Türkçeyle söylüyor: burada cihaz bu adrese 5 dakikada bir, çok düzenli
      bağlanmış. İşaret 'bak' demek, 'tehlike' değil; çoğu normal program."*
- [ ] `203.0.113.5` → **Şüpheli**: satır mavi şeritle en üste çıkar.
- [ ] Söyle: *"Analist işaretini koyuyor; şüpheliler en üstte kalıyor,
      tanıdıklar bir dahakine gizleniyor. İşaretler bu bilgisayarda bir
      dosyada duruyor."*

**2) Telemetri analizi (~1,5 dk)**
- [ ] "Dosya seç" → `data/samples/demo/dns.log` → **Analiz et**.
- [ ] Söyle: *"Elinizde bir Zeek kaydı ya da DNS CSV'si varsa toplayıcı
      olmadan da yükleyebilirsiniz. `malicious.example.test` tehdit listesinde,
      bilinen tehdit olarak en üstte. Cihaz incelemesi sekmesinde
      `updates.example.test`'in 2 dakikada bir sorulduğunu görüyoruz."*
- [ ] (Zaman kalırsa) `conn.log`: Bağlantı etkinliği → düzenli tekrar ve
      40 porta başarısız denemeler.

**3) Hızlı sorgu (~1 dk)**
- [ ] `malicious.example.test` → **Kontrol et** → **Bilinen tehdit**.
- [ ] Söyle: *"Tek bir adrese şüphelendiğinizde siteyi açmadan, DNS bile
      sormadan yerel tehdit listesine bakıyoruz. Kanıt tablosu hangi listede,
      ne zamandan beri olduğunu gösteriyor."*

**4) Gizlilik (~1 dk)**
- [ ] Söyle: *"Her şey bu bilgisayarda: sunucular yalnızca 127.0.0.1'de
      dinliyor, yüklediğiniz dosya bellekte işleniyor ve hiçbir yere
      gönderilmiyor, dışa aktarılan raporlarda istemci IP'leri yok. İnternete
      yalnızca siz bir düğmeye bastığınızda çıkıyor: CTI güncellemesi ya da
      site yaşı sorgusu."*
- [ ] (İsteğe bağlı) `ss -ltnp | grep -E ':8600|:8501'` çıktısını göster.

## 4. Uzun demo akışı (~12 dk)

**Bakılacaklar** (açılış ekranı)
- [ ] Koyu tema ve Türkçe geldiğini göster; üstte "· 10 sn'de bir güncellenir"
      ve yeşil nokta (taze rapor).
- [ ] 5 öğe: en üstte tehdit listesindeki `203.0.113.7` (kırmızı şerit).
- [ ] `203.0.113.5` → **Şüpheli**: mavi şeritle en üste çıkar, sayaç 1 olur.
- [ ] `198.51.100.77` → **Tanıyorum**: listeden gider, "Tanıdıklar (1)" altına
      düşer → **Geri getir**.
- [ ] Tehdit öğesine **Tanıyorum** de: tehdit listesindeki öğe görünür kalır.
- [ ] Bir satırın oku → "Neden? Ne yapmalı?" + dış siteler (uyarı metni: ad/IP o
      siteye gider; **tıklama**, sentetik adresler).
- [ ] Filtreler: Tehdit listesi / Bağlantılar / DNS sorguları.
- [ ] İşaretler Streamlit'le ortak: Streamlit'te aynı öğe aynı işaretle görünür.

**Ayrıntılar**
- [ ] Metrikler, inceleme özeti, üç onay kutusu (Streamlit varsayılanları).
- [ ] "Yalnızca inceleme gerektiren…" kapat → tablo büyür; ilk sütun sabit,
      tablo kendi içinde kayar.
- [ ] Bağlantı incelemesi: grup seç → inceleme rehberi + grafik (fare ya da ok
      tuşlarıyla ipucu) → "Tabloyu göster".
- [ ] DNS incelemesi: cihaz + domain seç → çubuk grafik.
- [ ] "Toplanan bağlantıların JSON raporunu indir": indirilen dosyada takma
      adlar var, gerçek IP yok.

**Hızlı sorgu**
- [ ] `https://malicious.example.test/login` → **Bilinen tehdit**, kanıt
      tablosu (Synthetic demo · phishing).
- [ ] `http://203.0.113.7/x` → HTTP uyarısı, ağ sahibi bölümü.
- [ ] `quiet.example.test` → **Düşük risk** ("garanti değil" açıklaması).
- [ ] **"Site yaşını kontrol et"e basma**: gerçek RDAP sunucusuna istek atar.
      Yalnızca düğmeye basınca ağa çıkıldığını anlat.

**Telemetri analizi**
- [ ] `dns.log`: Öncelikli bulgular → `malicious.example.test` (Bilinen
      Tehdit); Cihaz incelemesi → `updates.example.test` (İncele) ve DNS
      grafiği; Domain incelemesi → "Tam bilinen-domain IOC eşleşmesi".
- [ ] `conn.log`: Bağlantı etkinliği → `198.51.100.30` düzenli tekrar
      (IP'leri göster kutusu), TCP deneme incelemeleri → 40 port başarısız.
- [ ] `dns_queries.csv`: aynı sonuç, "Ayrılmış DNS tablosu" olarak algılanır;
      Sonuç filtresi "Bilinen Tehdit" → tek satır.
- [ ] Dışa aktar ve kaydet → JSON raporu: domain'ler var, istemci IP'si yok.
- [ ] **Yedek:** bu adım yeni arayüzde 3 denemede çalışmazsa (hata,
      boş sonuç), Streamlit'e geç: "Streamlit'te aç" → **Telemetri analizi**
      → aynı dosyayı yükle. Sonuçlar aynı fonksiyonlardan gelir.

**Kurulum ve CTI güncellemeleri**
- [ ] Çalışma modu, kayıtlı anahtarlar (Yok), CTI durumu, kaynak tablosu.
- [ ] Anahtar kutusuna yalnızca **sahte** bir değer yaz (örn. `demo-key`) →
      "Anahtarları uygula" → "Kayıtlı anahtarlar: ThreatFox, URLhaus", alan
      boşalır, değer bir daha gösterilmez → "Unut".
- [ ] **"CTI verilerini şimdi güncelle"ye basma**: internetten indirir.
- [ ] Otomatik güncelleme ayarını kaydet → sayfa yenilenince korunur.

**Son**
- [ ] EN düğmesi → her şey İngilizce; yenile → EN hatırlanır. TR'ye dön.
- [ ] Tema düğmesi → açık tema; yenile → hatırlanır; koyuya dön.
- [ ] "Streamlit'te aç" → taşınmayan ekranlar: Deneysel ML, Model
      değerlendirme, Analiz geçmişi; uygulamayı durdurma da orada.

## 5. Söylenmesi gereken sınırlar

- Taşınan: Bakılacaklar, Ayrıntılar (+ zaman çizelgeleri), Hızlı sorgu,
  Telemetri analizi, Kurulum ve CTI. Mantık yeniden yazılmadı; Streamlit'in fonksiyonları kullanılıyor ve
  bilinçli farklar dışında ekranlar Streamlit'le aynı.
- Bilinçli farklar: deneysel ML puanı ve "bu bilgisayardaki davranış" kartı
  Streamlit'te; analizde geçmişe kaydetme ve iki grafik (sonuç dağılımı ve
  ilişkili etkinlik; değerleri tablo/çubuk olarak var) yok; React'te girilen API anahtarları her zaman 0600 dosyaya
  kaydedilir (DEC-103); uygulamayı durdurma Streamlit'te.
- `threatfusion-ai start` henüz React'i açmıyor; kurulum Node gerektirip
  gerektirmeyeceği kararı sonraya kaldı.
- Bu bir arayüz değişikliği; P2 ölçümü ya da kullanıcı kabulü değildir.
  Gerçek trafikle yeniden ölçüm yapılmadı.

## 6. Yedek plan: Kali Linux (DENENMEDİ)

Ana makine çalışmazsa Kali'de kaynaktan çalıştırma. **Bu yol hiç denenmedi**;
kurulum betiği yalnızca temiz Debian 12 ve Ubuntu 24.04'te test edildi. Demodan
önce en az bir kez prova edilmeli, ağ gerektirir (~15 dk).

```bash
sudo apt-get update && sudo apt-get install -y git python3 python3-venv curl
git clone https://github.com/ConquestorYa/threatfusion-ai.git && cd threatfusion-ai
git switch feat/react-workspace          # ya da: git switch --detach demo-stable
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt && .venv/bin/pip install --no-deps -e .
curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash
. ~/.nvm/nvm.sh && nvm install 22
(cd web && npm ci && npm run build)
scripts/demo_web.sh
```

- Proje Python 3.12 ile test edildi; Kali'nin Python'u daha yeniyse
  bağımlılıklar kurulmayabilir (o durumda `uv` ya da `pyenv` ile 3.12).
- Sunucular yine yalnızca 127.0.0.1'de; gerçek veri, gerçek anahtar yok.

## 7. Bir şey ters giderse

| Belirti | Ne yap |
| --- | --- |
| "Yerel API yanıt vermiyor" | `scripts/demo_web.sh` çalışıyor mu? Ctrl+C ile durdurup yeniden başlat. |
| "Bu rapor bir dakikadan eski" | Toplayıcı durmuş; betiği yeniden başlat. |
| Sayfa beyaz/eski | `cd web && npm run build`, sonra sayfayı yenile. |
| Açılış açık temada ya da İngilizce | Tarayıcıdaki site verilerini temizle (`tf-theme`, `tf-lang`) ya da gizli pencere. |
| "Streamlit'te aç" açılmıyor | Streamlit portu farklıysa `STREAMLIT_PORT` ile başlat. |
| Port dolu | `API_PORT` / `STREAMLIT_PORT` ortam değişkenleriyle başka port seç. |
| Telemetri analizi hata veriyor | Dosyayı bir kez daha seç; 3 denemede olmazsa Streamlit'te aynı ekranı kullan (yukarıdaki yedek). |
| Yeni sürümde beklenmeyen bir sorun | Güvenli hale dön: `git switch --detach demo-stable && (cd web && npm ci && npm run build)` |
