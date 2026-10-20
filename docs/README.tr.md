# Dokümantasyon

[English](README.md) • **Türkçe**

## ThreatFusion'ı kullanmak

| Belge | İçerik |
| --- | --- |
| [Linux kurulumu](INSTALL_LINUX.tr.md) | Tek komutla kurulum, başlatma/durdurma, güncelleme, kaldırma, anahtarlar |
| [Zeek sensör kurulumu](ZEEK_SETUP.tr.md) | Kayıt üretmek: sensörün yeri, Docker tarifi, gizlilik |
| [Kullanım kılavuzu](USER_GUIDE.tr.md) | Sayfalar, toplayıcı, neler işaretlenir, inceleme, sınırlar |
| [Mimari](ARCHITECTURE.tr.md) | Veri akışı, kanıt modeli, depolama ve gizlilik |
| [Veri kaynakları](DATA_SOURCES.tr.md) | CTI kaynakları, lisanslar ve atıf |
| [Güvenlik politikası](../SECURITY.tr.md) | Güvenlik açığı bildirme, güvenli kullanım |

## Kanıtlar

Neyin, nasıl ölçüldüğü ve neyin başarısız olduğu. Her kayıt ait olduğu commit'i
ve protokolü belirtir; sonraki kod yeni ölçüm gerektirir. Kanıt belgeleri
İngilizcedir.

| Kayıt | Soru |
| --- | --- |
| [Gerçek trafik değerlendirmesi](evidence/REAL_TRAFFIC_EVALUATION.md) | İlk 24 saatin sonuçları, başarısız ilk 7 günlük deneme, yarıda kalan ikinci deneme ve 7 günlük deneme v3 |
| [İnceleme yükü](evidence/REVIEW_WORKLOAD.md) | Normal sentetik trafiğin ne kadarı İncele'ye giriyor; RITA ile karşılaştırma |
| [Ağ değerlendirmesi](evidence/NETWORK_EVALUATION.md) | Bağımsız IoT-23 kayıtları: neler bulundu, neler kaçırıldı |
| [Bağımsız tekrar oynatma](evidence/INDEPENDENT_REPLAY.md) | Bağımsız kayıtların toplayıcıdan yeniden geçirilmesi |
| [TCP sonlanması](evidence/TCP_TERMINATION.md) / [TCP denemeleri](evidence/TCP_ATTEMPT_REVIEW.md) | Canlı kontrollerle bağlantı durumu ve başarısız deneme kuralları |
| [Bağlantı incelemesi](evidence/CONNECTION_INVESTIGATION.md) / [DNS incelemesi](evidence/DNS_INVESTIGATION.md) / [DNS toplama](evidence/DNS_COLLECTION.md) | Canlı kontrollerle zaman çizelgesi, DNS kimliği ve geçiş sözleşmeleri |
| [Beklenen bağlantılar](evidence/EXPECTED_CONNECTIONS.md) | Bildirim kuralları ve kurgulanmış kontrolleri |
| [Toplayıcı](evidence/TELEMETRY_COLLECTOR.md) / [kapasite](evidence/CONNECTION_CAPACITY.md) / [kayıt hazırlama](evidence/LOG_PREPARATION.md) | Toplayıcı sözleşmeleri, kapasite ve büyük dosya hazırlama |
| [Çok günlük toplama](evidence/MULTIDAY_COLLECTION.md) / [operasyonel güven](evidence/OPERATIONAL_CONFIDENCE.md) | Döndürme, saklama, hata matrisi, gerçek zamanlı dayanıklılık testi, güvenlik incelemeleri |
| [Analist incelemesi](evidence/ANALYST_REVIEW.md) | İnceleme rehberi ve sentetik analist görevleri |
| [ML veri seti ve değerlendirmesi](evidence/ML_DATASET.md) | Alan adı ve yalnızca herkese açık veriyle eğitilen davranış modelleri (başarısız, kurulmadı), her bilgisayarda eğitilen davranış modeli (deneysel sekme), ritim skoru ve *Bu bilgisayar için yeni* |
| [Yerel laboratuvar](evidence/LOCAL_LAB.md) | Kontroller ve RITA karşılaştırması için kullanılan yalıtılmış laboratuvar |
| [Manuel kabul](evidence/MANUAL_ACCEPTANCE_TR.md) | Geliştiricinin manuel kabul kontrol listesi (Türkçe) |

Henüz ölçülmeyenler: gerçek zararlı yazılımda tespit oranı, gerçek trafikte bir
haftalık yanlış alarm (sürüyor), başka kullanıcılar için faydası.

## Geliştirme

Geliştirici kayıtları İngilizcedir.

| Belge | İçerik |
| --- | --- |
| [Ürün planı](dev/PRODUCT_PLAN.md) | Hedef, durum ve sıralı iş kuyruğu |
| [Kararlar](dev/DECISIONS.md) | Gerekçeleriyle numaralı tasarım kararları |
| [Proje bağlamı](dev/PROJECT_CONTEXT.md) | Güncel durum notu ve tarihli geçmiş |
| [Devir notu](dev/RELEASE_HANDOFF.md) | Son tamamlanan işler, kontroller ve sınırlılıklar |
