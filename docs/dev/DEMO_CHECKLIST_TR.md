# Pazartesi demosu: kontrol listesi (React çalışma alanı)

Branch: `feat/react-workspace` (PR #185, taslak; `main`'e birleştirilmedi).
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

## 3. Demo akışı (~12 dk)

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
- [ ] "Streamlit'te aç" → taşınmayan ekranlar: Telemetri analizi, Deneysel ML,
      Model değerlendirme, Analiz geçmişi; uygulamayı durdurma da orada.

## 4. Söylenmesi gereken sınırlar

- Taşınan: Bakılacaklar, Ayrıntılar (+ zaman çizelgeleri), Hızlı sorgu, Kurulum
  ve CTI. Mantık yeniden yazılmadı; Streamlit'in fonksiyonları kullanılıyor ve
  bilinçli farklar dışında ekranlar Streamlit'le aynı.
- Bilinçli farklar: deneysel ML puanı ve "bu bilgisayardaki davranış" kartı
  Streamlit'te; React'te girilen API anahtarları her zaman 0600 dosyaya
  kaydedilir (DEC-103); uygulamayı durdurma Streamlit'te.
- `threatfusion-ai start` henüz React'i açmıyor; kurulum Node gerektirip
  gerektirmeyeceği kararı sonraya kaldı.
- Bu bir arayüz değişikliği; P2 ölçümü ya da kullanıcı kabulü değildir.
  Gerçek trafikle yeniden ölçüm yapılmadı.

## 5. Bir şey ters giderse

| Belirti | Ne yap |
| --- | --- |
| "Yerel API yanıt vermiyor" | `scripts/demo_web.sh` çalışıyor mu? Ctrl+C ile durdurup yeniden başlat. |
| "Bu rapor bir dakikadan eski" | Toplayıcı durmuş; betiği yeniden başlat. |
| Sayfa beyaz/eski | `cd web && npm run build`, sonra sayfayı yenile. |
| Açılış açık temada ya da İngilizce | Tarayıcıdaki site verilerini temizle (`tf-theme`, `tf-lang`) ya da gizli pencere. |
| "Streamlit'te aç" açılmıyor | Streamlit portu farklıysa `STREAMLIT_PORT` ile başlat. |
| Port dolu | `API_PORT` / `STREAMLIT_PORT` ortam değişkenleriyle başka port seç. |
