# P0 manuel kabul testi — kontrol listesi

Bu liste [ürün planındaki](PRODUCT_PLAN.md) P0 kapısı içindir. P0 yalnızca
kullanıcının kendi sonuçlarıyla "geçti" sayılır; otomatik testler bunun yerine
geçmez. Her maddeyi işaretle. Bir sorun görürsen altına şu üç satırı yaz:

> **Ne yaptım:** … **Ne bekledim:** … **Ne oldu:** … (varsa ekran görüntüsü)

Başlamadan önce: bilgisayarda başka bir ölçüm (soak) çalışmıyor olmalı ve test
etmek istediğin düzeltmeler GitHub `main`'e gönderilmiş olmalı. Kurulum her zaman
`main`'deki güncel sürümü kurar.

## 1. Kurulum

- [ ] Normal kullanıcıyla (**sudo olmadan**) [README.tr.md](../README.tr.md)
      içindeki "Linux — tek komutla local kurulum" komutunu çalıştırdım.
- [ ] Kurulum hatasız bitti ve tarayıcıda `http://127.0.0.1:8501` (veya
      sıradaki boş port) açıldı.
- [ ] Uygulamalar menüsünde **ThreatFusion AI** kısayolu var.
- [ ] Yeni bir terminalde `threatfusion-ai` komutu bulunuyor.

## 2. Açma, kapatma, yeniden açma

- [ ] `threatfusion-ai status` çalışan sunucuyu gösteriyor.
- [ ] Tarayıcı sekmesini kapattım; `status` sunucunun hâlâ çalıştığını gösteriyor.
- [ ] `threatfusion-ai stop` sunucuyu durdurdu; `status` bunu doğruluyor.
- [ ] Menüden veya `threatfusion-ai` ile tekrar açtım; önceki ayarlar duruyor.
- [ ] Web panelindeki **Yerel uygulamayı kapat** düğmesi de sunucuyu durduruyor.

## 3. CTI anahtarları ve güncelleme

- [ ] Yan çubukta **Yerel kurulum ve CTI güncellemeleri** panelini buldum.
- [ ] Kendi ThreatFox ve URLhaus anahtarlarımı girip uyguladım.
- [ ] Kaynakları güncelledim; kaynak durumu "güncel" ve kayıt sayıları görünüyor.
- [ ] SGB ve PhishTank anahtarsız güncellendi.
- [ ] Anahtarı **kaydetmeden** uygulamayı kapatıp açtım; anahtar hatırlanmadı
      (beklenen davranış).
- [ ] Anahtarı açıkça kaydetmeyi seçtim; yeniden açınca hatırlandı.
- [ ] İnterneti kestim ve tekrar güncellemeyi denedim: anlaşılır bir hata
      gördüm ve **önceki veriler silinmedi**.
- [ ] İnterneti açıp tekrar güncelleyince düzeldi.

## 4. Quick Lookup

- [ ] Bilinen zararsız bir alan adı sorguladım (ör. `wikipedia.org`); sonuç ve
      gerekçesi anlaşılır.
- [ ] Bir IP adresi sorguladım; sonuç anlaşılır.
- [ ] Hatalı bir girdi denedim (ör. `abc def`); uygulama çökmeden açıklayıcı bir
      hata verdi.

## 5. Zeek log toplama

İkinci bir terminalde lab'ın ürettiği sentetik Zeek loglarından birini ver:

```bash
threatfusion-ai collect --input-dir /home/yahya/Work/threatfusion-lab/results/periodic-live-20261004T144348Z
```

- [ ] Komut hatasız çalıştı ve logları işledi.
- [ ] Web'de **Toplanan bağlantılar** sayfası bağlantı gruplarını gösteriyor.
- [ ] **Toplanan DNS gözlemleri** bölümü DNS sorgularını gösteriyor.
- [ ] Bir cihaz/hedef seçince zaman çizelgesi ve "neden incelenmeli" açıklaması
      anlaşılır.
- [ ] Ctrl+C ile durdurup aynı komutu tekrar çalıştırdım; aynı kayıtlar
      **ikinci kez eklenmedi**.

## 6. Dışa aktarma ve gizlilik

- [ ] Raporları JSON (ve varsa CSV) olarak indirdim.
- [ ] İndirilen dosyalarda IP'ler varsayılan olarak takma adla (`Host 001`,
      `Device 001` gibi) geliyor; gerçek IP yok.
- [ ] **Gözlenen cihaz IP'lerini yerelde göster** seçeneği yalnızca açıkça açınca
      gerçek IP'leri ekranda gösteriyor ve indirilen dosyaya eklemiyor.

## 7. Genel izlenim

- [ ] Bir analist olarak "hangi cihaza/hedefe neden bakmalıyım" sorusuna cevap
      bulabildim. Bulamadıysam nerede takıldığımı yazdım.
- [ ] Türkçe metinlerde anlamsız veya çevrilmemiş yer var mı? Varsa yazdım.

## Sonuç

- Tarih ve test edilen sürüm (`threatfusion-ai status` veya kurulum çıktısı):
- Bulunan sorunlar:
- Genel değerlendirme (geçti / sorunlu):
