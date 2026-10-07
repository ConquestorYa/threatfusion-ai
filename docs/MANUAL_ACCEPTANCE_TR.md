# P0 manuel kabul testi — kontrol listesi

Bu liste [ürün planındaki](PRODUCT_PLAN.md) P0 kapısı içindir. P0 yalnızca
kullanıcının kendi sonuçlarıyla "geçti" sayılır; otomatik testler bunun yerine
geçmez. Her maddeyi işaretle. Bir sorun görürsen altına şu üç satırı yaz:

> **Ne yaptım:** … **Ne bekledim:** … **Ne oldu:** … (varsa ekran görüntüsü)

`[evet]` olan maddeler tamamlandı; tekrar yapman gerekmiyor. "Sohbetten
aktarıldı" notlu olanları sen sohbette bildirdin, Claude işaretledi. Sırayla
**boş `[ ]` maddeleri** yap. Arayüz Türkçe ise düğme adları parantez içindeki
Türkçe karşılıklarıyla görünür.

## Testler dışında senden istenenler (genel kurallar)

- Bu dosyayı **bilgisayarındaki kopyada** düzenle
  (`~/Work/threatfusion-ai/docs/MANUAL_ACCEPTANCE_TR.md`) ya da sonuçları
  sohbete yaz. GitHub web sitesinde düzenleme; Claude yerelde değişiklik
  yaparken çakışma olur.
- Claude Code'u yeni bir oturum için proje klasöründen başlat:
  `cd ~/Work/threatfusion-ai && claude`. Aynı anda bu repoda tek Claude
  oturumu çalışsın.
- Bölüm 5'te yalnızca listedeki klasörü kullan; `reserved` adlı klasörleri açma.
- API anahtarlarını sohbete, bu dosyaya veya GitHub'a yazma.
- [evet] Render: servis silindi, Blueprint bağlantısı koparıldı (artık bir şey
  yapman gerekmiyor).

## 0. Başlamadan önce: en son sürüme güncelle

Claude doğrulanmış her düzeltmeyi GitHub `main`'e gönderir. Kurulum komutu her
çalıştığında `main`'deki **en son** sürümü kurar; tekrar çalıştırmak güncelleme
yapar. Silip yeniden kurman gerekmez; CTI verileri, ayarlar ve kayıtlı
anahtarlar korunur.

1. Uygulamayı durdur:

   ```bash
   threatfusion-ai stop
   ```

2. [README.tr.md](../README.tr.md) içindeki **aynı tek satırlık kurulum
   komutunu** tekrar çalıştır. Bitince uygulama tarayıcıda açılır.
3. Kurulu sürümü kontrol et:

   ```bash
   grep -o 'releases/[0-9a-f]\{7\}' ~/.local/share/threatfusion-ai/installation.json
   ```

   Çıkan 7 karakter, GitHub'daki son commit'in ilk 7 karakteriyle aynı olmalı
   (repo sayfasında commit listesinin en üstü ya da Claude'un son mesajında
   söylediği commit).

- [ ] Güncelledim; kurulu sürüm son commit ile aynı: `…….`

Adres `http://127.0.0.1:` veya `http://localhost:` ile başlamalı (port 8501,
8502… olabilir); başka adreslerle güvenlik gereği boş sayfa görünür.

## 1. Kurulum

- [evet] Normal kullanıcıyla (**sudo olmadan**) README.tr.md içindeki
      "Linux — tek komutla local kurulum" komutunu çalıştırdım.
- [evet] Kurulum hatasız bitti ve tarayıcıda uygulama açıldı.
- [evet] Uygulamalar menüsünde **ThreatFusion AI** kısayolu var.
- [evet] Yeni bir terminalde `threatfusion-ai` komutu bulunuyor.
- [evet — sohbetten aktarıldı] Aynı komutu tekrar çalıştırınca güncellendi;
      CTI verileri ve kayıtlı anahtarlar korundu. (Omarchy/Arch üzerinde.)

## 2. Açma, kapatma, yeniden açma

- [evet] `threatfusion-ai status` çalışan sunucuyu gösteriyor.
- [evet] Tarayıcı sekmesini kapattım; `status` sunucunun hâlâ çalıştığını gösteriyor.
- [evet] `threatfusion-ai stop` sunucuyu durdurdu; `status` bunu doğruluyor.
- [evet] Menüden veya `threatfusion-ai` ile tekrar açtım; önceki ayarlar duruyor:
  - [evet] Yan çubuktaki mod seçimi (gerçek CTI / demo) aynı.
  - [evet — sohbetten aktarıldı] CTI kayıt sayıları ve "son güncelleme" zamanı
        korunuyor (yeniden açınca kaynaklar "Fresh" göründü).
  - [evet — sohbetten aktarıldı] **"Uygulama çalışırken otomatik güncelle"** kutusunu işaretle, aralığı
        12 saat seç, **"Güncelleme ayarlarını kaydet"**e bas. Uygulamayı kapatıp
        aç: kutu işaretli ve aralık 12 saat kalmalı. (Sonra istediğin gibi geri al.)
  - Dil seçimi bilerek kalıcı değildir; yeniden açınca varsayılana dönmesi normal.
- [evet] Web panelindeki **Yerel uygulamayı kapat** düğmesi de sunucuyu durduruyor.

## 3. CTI anahtarları ve güncelleme

Hepsi yan çubuktaki **Yerel kurulum ve CTI güncellemeleri** panelinde.
ThreatFox ve URLhaus **senin anahtarını** ister; SGB ve PhishTank anahtarsızdır.

Tamamlananlar:

- [evet] Paneli buldum.
- [evet] Kendi ThreatFox ve URLhaus anahtarlarımı girip uyguladım.
- [evet] Anahtarı **kaydetmeden** uygulamayı kapatıp açtım; anahtar hatırlanmadı
      (beklenen davranış).
- [evet — sohbetten aktarıldı] Anahtarı açıkça kaydetmeyi seçtim; yeniden açınca hatırlandı.
- [evet] SGB ve PhishTank anahtarsız güncellendi.
  - Not: PhishTank'tan aslında hiç kayıt gelmedi. Sebep PhishTank'ın kendisi:
    anahtarsız public indirme adresi şu an çalışmıyor. Bu senin hatan değil.

Yapılacaklar (sırayla):

- [evet — sohbetten aktarıldı: "CTI is already up to date…" mesajı çıktı;
  "sonraki indirme" yazısı ayrıca bildirilmedi] **Zaten güncel durumu:** Kutuyu işaretlemeden **Update CTI now**
      (**CTI verilerini şimdi güncelle**) düğmesine bas. Birkaç saniye içinde
      "CTI zaten güncel; indirilecek bir şey yoktu" mesajı çıkmalı ve düğme
      tekrar tıklanabilir olmalı. Panelde "Kaynaklar güncel; sonraki indirme
      yaklaşık … saat sonra" yazmalı.
- [ ] **Gerçek indirme:** **"Kaynaklar güncel olsa da yeniden indir"** kutusunu
      işaretle ve düğmeye bas. Kontrol et:
  - [evet — sohbetten aktarıldı] Köşede "CTI güncellemesi başladı" bildirimi çıktı.
  - [evet — sohbetten aktarıldı: bar doldu] Sayfanın üstünde ilerleme çubuğu var: "x/y tamamlandı · %…, kaynak,
        aşama". SGB sırasında "… / … kayıt" sayacı ilerliyor. Yüzde tamamlanan
        kaynakları sayar (indirme boyutları önceden bilinmez).
  - [evet — sohbetten aktarıldı] Güncelleme sürerken düğme ve kutu gri/tıklanamaz.
  - [sorunlu — sohbetten aktarıldı: başka sayfaya geçince çubuk devam etti ama
    web arayüzünde bir anlık hata çıkıp kayboldu; terminalde
    "sqlite3.OperationalError: database is locked"] Güncelleme sürerken başka
        sayfaya geçtim ve dili değiştirdim; çubuk durmadan devam etti.
    - **Tur 5 — düzeltildi, yeniden test et:** Güncelleme veritabanına yazarken
      yan paneldeki durum bölümü okuyamıyordu. Artık veritabanı okumaları
      yazmayı beklemiyor.
      - [ ] "Yeniden indir" kutusuyla güncelleme sürerken sayfalar arasında
            gezindim, dili değiştirdim ve bir **hızlı sorgu** yaptım: web
            arayüzünde ve uygulamayı başlattığın terminalde hata çıkmadı.
  - [evet — sohbetten aktarıldı: "CTI update finished: 3 source(s) downloaded"]
        Bitince "CTI güncellemesi tamamlandı: … kaynak indirildi" mesajı çıktı,
        düğme tekrar aktif oldu, kayıt sayıları güncellendi.
  - [ ] Panelde PhishTank için **mavi** bilgi notu var ("anahtarsız public kaynak
        şu an alınamıyor; senin tarafında düzeltilecek bir şey yok").
  - [ ] Toplam süre: … dakika (SGB eskisine göre daha kısa sürmeli).
- [ ] **İnternetsiz:** Wi-Fi'ı kapat, kutuyu işaretli bırak ve düğmeye bas.
      Birkaç saniye içinde "Hiçbir CTI kaynağına ulaşılamadı. İnternet
      bağlantını kontrol et; mevcut veriler korunuyor" mesajı çıkmalı, düğme
      tekrar aktif olmalı ve **kayıt sayıları değişmemeli**. Panelde
      "anahtarını kontrol et" yazmamalı.
- [ ] Wi-Fi'ı aç, kutu işaretliyken tekrar bas: güncelleme başarıyla bitti.

## 4. Hızlı sorgu (Quick lookup)

Ana sayfadaki **Hızlı sorgu** alanını kullan. Hiçbir sorgu hedef siteye
bağlanmaz; yalnızca yerel CTI verisine bakılır.

- [ ] `wikipedia.org` sorguladım: eşleşme olmadığı ve bunun "kesin güvenli"
      anlamına gelmediği anlaşılır biçimde yazıyor.
- [ ] Bir IP adresi sorguladım (ör. `8.8.8.8`); sonuç anlaşılır.
- [ ] Hatalı bir girdi denedim (ör. `abc def`): uygulama çökmedi, Türkçe bir
      hata çıktı ("Girdi analiz edilemedi: alan adı en az iki bölümden oluşmalı…").

## 5. Zeek log toplama

Bu adım için lab'daki **sentetik** veri setini kullan (gerçek trafik değil,
inceleme gerektiren örnekler içerir). Uygulama açıkken **ikinci bir
terminalde** çalıştır:

```bash
threatfusion-ai collect --input-dir /home/yahya/Work/threatfusion-lab/analyst-guidance-v1/traffic/development/zeek
```

Testte başka bir klasör verme (her toplayıcı durumu tek bir kaynağa
bağlıdır). `reserved` adlı klasörleri kullanma; onlar değerlendirme için
ayrılmıştır.

- [ ] Komut hatasız çalıştı. Terminalde ilk satırda `"new_records": 818` ve
      `"review_groups": 8` görünüyor; sonraki satırlarda `"new_records": 0`.
- [ ] Yan çubukta **İkincil görünümler → Toplanan bağlantılar** sayfasını açtım;
      tabloda 8 inceleme grubu var. Uçlar `Sistem 001` gibi takma adlarla görünüyor.
- [ ] Bir grubu seçtim; zaman çizelgesi ve **İnceleme rehberi** (neden incelenmeli, sonra neye bakılmalı) bölümü
      anlaşılır.
- [ ] Aynı sayfadaki **Toplanan DNS gözlemleri** bölümünde 1 inceleme grubu
      görünüyor. "İnceleme önceliği olmayan gözlemleri de göster" kutusuyla diğer
      DNS kayıtları da görünüyor.
- [ ] Ctrl+C ile toplayıcıyı durdurup aynı komutu tekrar çalıştırdım; terminalde
      `"new_records": 0` görünüyor, kayıtlar **ikinci kez eklenmedi**.

## 6. Dışa aktarma ve gizlilik

**Toplanan bağlantılar** sayfasında:

- [ ] **Toplanan bağlantıların JSON raporunu indir** ile raporu indirdim.
- [ ] Dosyayı açtım: cihazlar `Host 002`, `Device 006` gibi takma adlarla
      geçiyor; gerçek IP adresi yok.
- [ ] **"Gözlenen cihaz IP'lerini yerelde göster; indirmeler takma adları
      korur"** kutusunu işaretleyince gerçek IP'ler yalnızca ekranda göründü.
      Raporu tekrar indirince dosyada yine takma adlar var.

## 7. Genel izlenim

- [ ] Bir analist olarak "hangi cihaza/hedefe neden bakmalıyım" sorusuna cevap
      bulabildim. Bulamadıysam nerede takıldığımı yazdım.
- [ ] Türkçe metinlerde anlamsız veya çevrilmemiş yer var mı? Varsa yazdım.

## Sonuç

- Tarih ve test edilen sürüm (kurulum çıktısı veya `threatfusion-ai status`):
- Bulunan sorunlar:
- Genel değerlendirme (geçti / sorunlu):

## Önceki turlarda bildirilen sorunlar (kayıt)

- Tur 1 — kullanıcının notu: "Update CTI now tuşuna basınca güncelliyor. Ama aynı
  tuşa tekrar basınca durduruyor galiba orda hata var mı bak (ayrıca güncelleme
  kısmında bar veya %71 gibi bir değer ekle çünkü uzun sürüyor ve sadece dönüp
  duran küçük bir ikon var. pop up gibi ortada çıkabilir güncelleniyor diye)".
  Durum: düzeltildi (arka planda güncelleme, ilerleme çubuğu, bildirimler).
- Tur 1 — "önceki ayarlardan kasıt ne anlamadım". Durum: madde netleştirildi.
- Tur 2 — PhishTank her güncellemede "anahtarını kontrol et" uyarısı veriyordu.
  Durum: kaynak kaynaklı kesinti olarak mavi notla gösteriliyor.
- Tur 3 — internetsiz denemede sonuç görünmüyordu, SGB çok yavaştı, kaynaklar
  güncelken düğme işlevsiz görünüyordu. Durum: kalıcı sonuç mesajları, düğme
  bitişte yeniden aktif, "yeniden indir" seçeneği, SGB 4 paralel sayfa.
- Tur 5 — güncelleme sırasında sayfa değişince "database is locked" hatası.
  Durum: CTI önbelleği WAL moduna alındı (okumalar yazmayı beklemiyor),
  bağlantılar her kullanımdan sonra kapatılıyor, durum paneli kilitte hata
  yerine bilgi notu gösteriyor.
- Tur 4 — hızlı sorgunun hata ayrıntıları İngilizceydi; Bölüm 5'teki eski örnek
  veri inceleme grubu üretmediği için tablolar boş görünecekti. Durum: çeviriler
  eklendi, örnek veri değiştirildi.
