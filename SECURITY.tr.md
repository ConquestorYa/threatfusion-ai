# Güvenlik politikası

[English](SECURITY.md) • **Türkçe**

## Güvenlik açığı bildirme

ThreatFusion AI'da olası bir güvenlik sorunu bulursan, lütfen bu depoda bir
GitHub Security Advisory taslağı açarak özel olarak bildir:

- Depo -> **Security** -> **Advisories** -> **Report a vulnerability**

Özel güvenlik açığı bildirimi kullanılamıyorsa, depo sahibine GitHub profilinde
belirtilen özel bir kanal üzerinden ulaş. Özel bir kanal yoksa herkese açık bir
issue'da gizli bilgi, özel telemetri ya da istismar ayrıntısı paylaşma.

Lütfen şunları ekle:

- etkilenen bileşen/dosya
- yeniden üretme adımları
- beklenen ve gerçekleşen davranış
- olası etki
- varsa önerilen çözüm

## Yanıt beklentileri

- İlk geri dönüş hedefi: **7 gün içinde**
- Değerlendirme/güncelleme hedefi: **14 gün içinde**
- Düzeltme süresi: önem derecesine, karmaşıklığa ve geliştiricinin müsaitliğine
  bağlıdır

## Kapsam

Kapsam içinde:

- depodaki kaynak kod, betikler ya da kapsayıcı paketlemesindeki güvenlik
  açıkları
- veri ayrıştırma, depolama, dışa aktarma ya da dağıtım varsayılanlarında
  güvenliği etkileyen sorunlar

Kapsam dışında:

- üçüncü taraf sistemlere karşı aktif tarama yapılması talepleri
- güvenli biçimde paylaşılamayan özel telemetriye erişim gerektiren raporlar

## Güvenli kullanım beklentileri

CTI anahtarları uygulamayı çalıştıran kullanıcıya ait olmalıdır. Pakette
geliştirici anahtarı ya da paylaşılan bir yedek anahtar yoktur. Linux ilk
çalıştırma profili anahtarları kurulum meta verisinin ve Streamlit alt işlem
ortamının dışında tutar. Varsayılan demo anahtar gerektirmez; eksik anahtarlar
ilgili anahtarlı beslemenin atlanmasına yol açar. Güncelleme tanılamaları ham
istisna metnini ve kimlik bilgisi içeren URL'leri göstermez. `.env`, Streamlit
`secrets.toml` ve özel anahtar dosyaları yerelde kalmalıdır; yayın denetimi
bunları hem izlenen dosyalarda hem de erişilebilir Git geçmişinde reddeder.
Özel CTI/veri seti/model/telemetri dosyaları dağıtılmamalıdır.

Kullanıcıları ve geliştiriciyi korumak için:

- raporlara gizli bilgi, API anahtarı ya da özel telemetri ekleme
- tehdit URL'lerini/alan adlarını/IP'lerini/hash'lerini yalnızca etkisiz metin
  verisi olarak ele al
- geliştirici düzeltmeyi ya da azaltma önerisini doğrulayana kadar herkese açık
  paylaşımdan kaçın
