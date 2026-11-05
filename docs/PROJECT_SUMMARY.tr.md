# Proje özeti

[English](PROJECT_SUMMARY.md) • **Türkçe**

ThreatFusion AI'ın tek sayfalık özeti. Aşağıdaki her sayı
[kanıt kayıtlarından](README.tr.md#kanıtlar) alınmıştır; burada onlardan daha
yeni bir bilgi yoktur.

## Problem

Küçük bir ağ (ev, laboratuvar, küçük ofis) günde binlerce bağlantı üretir.
Bunların arasından zararlı yazılımın "eve haber vermesine" benzeyen birkaçını
bulmak genellikle tam bir izleme platformu (SIEM, Security Onion, Malcolm) ya
da ham Zeek kayıtları üzerinde elle çalışma gerektirir. ThreatFusion daha dar
bir soru sorar: **Hangi cihaz hangi hedefle konuştu, bunlardan hangileri daha
yakından bakılmayı hak ediyor ve neden?**

## Yaklaşım

1. **Topla.** Yerel bir toplayıcı tamamlanmış Zeek `conn.log` ve `dns.log`
   dosyalarını içe aktarır ve son 24 saati özel bir SQLite veritabanında tutar.
2. **Kontrol et.** Her hedef üç tehdit istihbaratı (CTI) listesiyle
   karşılaştırılır: SGB (Türkiye), ThreatFox ve URLhaus. Her cihaz → hedef
   grubu ayrıca basit ve açıklanabilir davranış kurallarıyla kontrol edilir:
   uzun oturumlar (≥ 1 saat), düzenli tekrar (30+ dakika boyunca çok düzenli
   aralıklarla 20+ bağlantı) ve başarısız deneme örüntüleri.
3. **Açıkla.** *İncelenecekler* listesi yalnızca işaretlenen grupları gösterir;
   önce CTI eşleşmeleri gelir ve her birinin nedeni, kanıtı ve kapsam sınırları
   yazar.

**Tespiti CTI eşleştirmesi ve bu kurallar yapar.** Kanıtlar güçlerine göre
ayrı tutulur (tam CTI eşleşmesi > CTI bağlamı > davranış) ve tek bir kapalı
puanda birleştirilmez.

## Makine öğrenmesinin yeri

Makine öğrenmesi **deneyseldir** ve ayrı bir sekmede durur. İnceleme listesini
hiçbir zaman değiştirmez ve CTI'ın önüne geçmez.

- *Bu bilgisayar için yeni*: Bir cihazın daha önce hiç kullanmadığı ve düzenli
  bir ritimle aramaya devam ettiği hedefler.
- Her bilgisayarda, o bilgisayarın 3 günlük kendi trafiği ve kurulumla gelen
  herkese açık kayıtların sayısal özellikleriyle yerelde eğitilen bir random
  forest davranış modeli.

Daha önceki modeller (alan adına bakan sözcüksel bir sınıflandırıcı ve yalnızca
herkese açık veriyle eğitilen bir model) değerlendirmelerini geçemedi ve
kapatıldı. Başarısızlıklar dahil tüm geçmiş
[ML değerlendirmesi](evidence/ML_DATASET.md) belgesindedir (İngilizce).

## Kısaca mimari

Zeek kayıtları → toplayıcı (kontrol noktalı, tekrarları ayıklanmış, sınırlı
kanıt penceresi) → takma adlı JSON anlık görüntüsü → `127.0.0.1`'e bağlı
Streamlit web uygulaması. CTI listeleri yerelde önbelleğe alınır; şüpheli
hedeflere asla bağlanılmaz ve çözümlenmez, hiçbir veri bilgisayardan çıkmaz.
Ayrıntılar: [Mimari](ARCHITECTURE.tr.md).

Teknolojiler: Python 3.12, Streamlit, SQLite, pandas, scikit-learn. Yalnızca
Linux.

## Şimdiye kadarki sonuçlar

| Ölçülen | Sonuç |
| --- | --- |
| Sentetik normal ve benzetilmiş trafik | Normal güncelleyiciler ve yoklamalar da İncele'ye giriyor: kurallar henüz yeterince seçici değil |
| Dört IoT-23 kaydı (2018–2019) | İki zararsız kayıtta 0 inceleme; iki zararlı kayıttan biri bir inceleme üretti, diğeri hiç üretmedi |
| Hata matrisi ve 6 saatlik dayanıklılık testi | 9/9 hata senaryosu geçti; dayanıklılık testi 16/16 kontrolü geçti (toplayıcı en fazla 684 MiB) |
| Bir dizüstü bilgisayar, 24 saat normal gerçek trafik | 59 inceleme grubu, hepsi zararsız; bunun arkasındaki kusurlar düzeltildi |
| Her bilgisayarda eğitilen davranış modeli | Görülmemiş bir cihazda zararlı ailelerin %71'i, görülmemiş zararlı kayıtların %56'sı, günde en fazla 1 yanlış işaret; 2025–2026 zararlılarının yalnızca %27'si |
| Mühendislik | CI'da lint, yaklaşık 1.400 otomatik test, depo gizlilik denetimi, konteyner kontrolü ve temiz Debian ile Ubuntu'da ilk kurulum testleri çalışır |

## Sınırlamalar

- Gerçek ve etiketli zararlı yazılımı yakalama oranı **henüz ölçülmedi**.
- Gerçek trafikte 7 günlük yanlış alarm testi sürüyor.
- Davranış kuralları normal yazılımlarla da (güncelleyiciler, sohbet
  uygulamaları) eşleşebilir; her işaret bir hüküm değil, bakmak için bir
  nedendir.
- RITA, Security Onion ya da Malcolm'dan daha faydalı olup olmadığı
  ölçülmedi.
- Yalnızca Linux; Zeek ayrıca çalıştırılmalıdır.

## Deneyin

[Kurulumdan](INSTALL_LINUX.tr.md) sonra uygulamayı sentetik veriyle açın:

```bash
threatfusion-ai --mode demo
```

Demo sonuçları ölçüm değildir.
