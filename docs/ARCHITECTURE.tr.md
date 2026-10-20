# Mimari

[English](ARCHITECTURE.md) • **Türkçe**

ThreatFusion yerel ve pasif bir ağ inceleme aracıdır. Zeek kayıtlarını ve tehdit
istihbaratı (CTI) listelerini okur; cihaz → hedef gruplarından oluşan bir
kuyruğu, her birinin neden dikkat gerektirebileceğiyle birlikte gösterir.
Şüpheli hedefler veri olarak ele alınır: asla ziyaret edilmez ya da çözümlenmez.

## Veri akışı

~~~mermaid
flowchart LR
    subgraph SENSOR["Sensörün"]
        ZEEK[Zeek: conn.log + dns.log<br/>saatlik döndürülür]
    end
    subgraph CTI["CTI kaynakları"]
        SGB[SGB]
        TF[ThreatFox]
        UH[URLhaus]
    end
    SGB & TF & UH -->|Kurulum ve CTI güncellemeleri| CACHE[(Yerel CTI önbelleği<br/>SQLite)]
    ZEEK -->|tamamlanmış dosyalar| COLLECTOR[Toplayıcı<br/>threatfusion-ai collect]
    CACHE --> COLLECTOR
    COLLECTOR --> STATE[(Özel durum<br/>24 sa kanıt)]
    STATE --> SNAPSHOT[Takma adlı anlık görüntü<br/>JSON]
    SNAPSHOT --> UI[Web uygulaması<br/>Toplanan bağlantılar]
    STATE -->|salt okunur| ML[Deneysel ML sekmesi<br/>Bu bilgisayar için yeni<br/>davranış modeli]
    ML <--> MEMORY[(Özel hedef belleği,<br/>günlük örnekler, yerel model)]
    PACK[Gönderilen herkese açık<br/>öznitelikler] --> ML
    ML --> UI
    UPLOAD[Yüklenen dosya] --> ANALYSIS[Tek seferlik analiz] --> UI
    CACHE --> ANALYSIS
    CACHE --> LOOKUP[Hızlı sorgu] --> UI
~~~

- **Toplayıcı** yalnızca kapanmış Zeek dosyalarını içe aktarır, kontrol
  noktalarıyla tekrarları önler, sınırlı bir kanıt penceresini özel bir SQLite
  veritabanında tutar ve her değişiklikten sonra atomik bir JSON anlık görüntüsü
  yazar.
- **Web uygulaması** ham kayıtları ya da veritabanını değil, bu anlık görüntüyü
  okur. Gerçek uç nokta IP'leri yalnızca açıkça istendiğinde, ayrı bir özel
  dosyadan gösterilir.
- **CTI güncellemeleri** kurulum sayfasından çalışır (elle ya da uygulama
  çalışırken 6/12/24 saatte bir). Her kaynak bağımsız güncellenir; başarısız bir
  güncelleme eski veriyi korur.
- **Deneysel ML sekmesi** toplayıcı veritabanını salt okunur biçimde okur,
  cihazların hangi hedefleri kullandığına dair özel bir bellek tutar ve sabit bir
  ritimle aranan yeni hedefleri listeler. Ayrıca bilgisayarın bağlantı
  gruplarından günlük örnekler saklar ve bunlarla, gönderilen herkese açık
  özniteliklerle birlikte, yerelde bir davranış rastgele ormanı (random forest)
  eğitir. İnceleme listesini asla değiştirmez.

## Kanıt modeli

Kanıtlar güçlerine göre ayrı tutulur ve asla tek bir skorda birleştirilmez.

1. **Tam CTI eşleşmesi** (listedeki bir alan adı, URL ya da IP): en güçlü kanıt;
   DNS grupları *Bilinen tehdit* olur.
2. **CTI bağlamı** (bir yanıt IP'si ya da listelenmiş bir URL'nin ana makine adı
   eşleşir): gösterilir, ancak tam eşleşmeden zayıftır.
3. **Davranış**: uzun oturumlar, düzenli tekrar, başarısız deneme desenleri ve
   DNS hacim/zamanlama sinyalleri. Bunlar *İncele* düzeyini yükseltir; asla
   zararlı yazılım kanıtı olarak sunulmaz. Kurallar:
   [kullanım kılavuzu](USER_GUIDE.tr.md#neler-işaretlenir).
4. **Deneysel ML**, inceleme listesinden ayrı gösterilir: *Bu bilgisayar için
   yeni* (hedef belleği + sabit bir ritim skoru, geliştirme düzeyinde ölçüldü) ve
   bu bilgisayarda eğitilen bir ormandan gelen davranış modeli skoru
   (`ml_local.py`, `ml-behavior-local-v1` ile ölçüldü). Eski sözcüksel alan adı
   skoru kapalıdır. ML asla CTI'ı geçersiz kılmaz.

İşaretlenen her grup nedenlerini ve kapsam sınırlarını (eksik alanlar,
tamamlanmamış oturumlar, yetersiz gözlem) listeler.

## Gizlilik ve depolama

| Saklananlar | Saklanmayanlar |
| --- | --- |
| CTI önbelleği ve güncelleme durumu | Paket içerikleri (Zeek yalnızca bağlantı ve DNS meta verisi yazar) |
| Toplayıcı durumu: kanıt penceresi için türlendirilmiş bağlantı/DNS kayıtları, kontrol noktaları | Yüklenen dosyalar ve ham satırları |
| Rapora özgü takma adlı anlık görüntüler (`Host 1`, `Device 1`) | API anahtarları (kaydetmeyi seçmedikçe; o durumda yalnızca sahibinin okuyabildiği bir dosya) |
| Yerel gösterim için özel bir takma ad → IP eşlemesi | Makinenin dışına çıkan hiçbir şey: telemetri yüklemesi yoktur |
| Deneysel ML sekmesinin hedef belleği, günlük örnekleri ve yerel modeli (`ml/baseline.json`, `ml/local-days.json`, `ml/behavior-model.json`) ve inceleme işaretlerin | |

Durum dizinleri yalnızca sahibine açıktır (0700, dosyalar 0600). Uygulama
127.0.0.1 adresine bağlanır ve Host başlığı yerel olmayan istekleri reddeder
(DNS rebinding koruması).

## Ana modüller

| Alan | Modüller |
| --- | --- |
| CTI | `collectors/`, `cti_cache.py`, `cti_refresh.py`, `matching.py` |
| Toplayıcı | `telemetry_collector.py`, `collector_reports.py`, `collector_identity.py`, `log_preparation.py` |
| Tespit | `connections.py`, `connection_attempts.py`, `device_triage.py`, `dns_behavior.py`, `hybrid_assessment.py` |
| İnceleme görünümleri | `connection_timeline.py`, `dns_timeline.py`, `expected_connections.py` |
| Yükleme analizi | `dns_ingest.py`, `network_telemetry.py`, `runtime_analysis.py` ve biçim bağdaştırıcıları |
| Web uygulaması | `streamlit_app.py`, `ui_*.py`, `local_workspace.py`, `request_guard.py` |
| Kurulum aracı | `scripts/install_linux.sh`, `scripts/bootstrap_linux.py`, `local_setup.py` |
| Deneysel ML | `baseline.py`, `rhythm.py`, `ml_behavior.py`, `ml_local.py` (+ `models/`), `ui_new_destinations.py`, `ui_behavior.py`; sözcüksel model `ml_*.py` ([değerlendirme geçmişi](evidence/ML_DATASET.md), İngilizce) |

Tasarım kararları ve gerekçeleri: [DECISIONS.md](dev/DECISIONS.md) (İngilizce).
