# P0 manuel kabul testi — kontrol listesi

Bu liste [ürün planındaki](PRODUCT_PLAN.md) P0 kapısı içindir. P0 yalnızca
kullanıcının kendi sonuçlarıyla "geçti" sayılır; otomatik testler bunun yerine
geçmez. Her maddeyi işaretle. Bir sorun görürsen altına şu üç satırı yaz:

> **Ne yaptım:** … **Ne bekledim:** … **Ne oldu:** … (varsa ekran görüntüsü)

Başlamadan önce: bilgisayarda başka bir ölçüm (soak) çalışmıyor olmalı ve test
etmek istediğin düzeltmeler GitHub `main`'e gönderilmiş olmalı. Kurulum her zaman
`main`'deki güncel sürümü kurar.

## 1. Kurulum

- [evet] Normal kullanıcıyla (**sudo olmadan**) [README.tr.md](../README.tr.md)
      içindeki "Linux — tek komutla local kurulum" komutunu çalıştırdım.
- [evet] Kurulum hatasız bitti ve tarayıcıda `http://127.0.0.1:8501` (veya
      sıradaki boş port) açıldı.
- [evet] Uygulamalar menüsünde **ThreatFusion AI** kısayolu var.
- [evet] Yeni bir terminalde `threatfusion-ai` komutu bulunuyor.

## 2. Açma, kapatma, yeniden açma

- [evet] `threatfusion-ai status` çalışan sunucuyu gösteriyor.
- [evet] Tarayıcı sekmesini kapattım; `status` sunucunun hâlâ çalıştığını gösteriyor.
- [evet] `threatfusion-ai stop` sunucuyu durdurdu; `status` bunu doğruluyor.
- [önceki ayarlardan kasıt ne anlamadım] Menüden veya `threatfusion-ai` ile tekrar açtım; önceki ayarlar duruyor.
  - **Tur 2 — yeniden test et (madde netleştirildi):** "Ayarlar" şunlar demek:
    - [ ] Yan çubuktaki mod seçimi (gerçek CTI / demo) kapatmadan önceki gibi.
    - [ ] "Otomatik güncelleme" kutusu ve güncelleme aralığı (değiştirdiysen)
          kapatmadan önceki gibi.
    - [ ] Güncellediğin CTI kaynaklarının kayıt sayıları ve son güncelleme zamanı
          hâlâ görünüyor (veriler silinmemiş).
    - Dil seçimi bilerek kalıcı değildir; yeniden açınca varsayılana dönmesi normal.
- [evet] Web panelindeki **Yerel uygulamayı kapat** düğmesi de sunucuyu durduruyor.

## 3. CTI anahtarları ve güncelleme

- [evet] Yan çubukta **Yerel kurulum ve CTI güncellemeleri** panelini buldum.
- [evet] Kendi ThreatFox ve URLhaus anahtarlarımı girip uyguladım.
- [Update CTI now tuşuna basınca güncelliyor. Ama aynı tuşa tekrar basınca durduruyor galiba orda hata var mı bak (ayrıca güncelleme kısmında bar veya %71 gibi bir değer ekle çünkü uzun sürüyor ve sadece dönüp duran küçük bir ikon var. pop up gibi ortada çıkabilir güncelleniyor diye)] Kaynakları güncelledim; kaynak durumu "güncel" ve kayıt sayıları görünüyor.
  - **Tur 2 — düzeltildi, yeniden test et:** Hata doğrulandı: güncelleme
    sürerken herhangi bir tıklama güncellemeyi yarıda kesiyordu. Artık arka
    planda çalışıyor.
    - [ ] "Update CTI now"a basınca sağ üstte "güncelleme başladı" bildirimi çıktı.
    - [ ] Sayfanın üstünde ilerleme çubuğu var: "x/y tamamlandı · %..., kaynak
          adı, aşama". Yüzde tamamlanan kaynakları sayar (indirme boyutu
          önceden bilinmez); SGB sayfalarında ara değerler görünür.
    - [ ] Güncelleme sürerken düğme pasif (gri) ve tıklanamıyor.
    - [ ] Güncelleme sürerken başka sayfaya geçtim / dili değiştirdim; güncelleme
          durmadı, çubuk ilerlemeye devam etti.
    - [ ] Bitince "CTI güncellemesi tamamlandı" bildirimi çıktı, çubuk kayboldu
          ve kaynak kayıt sayıları göründü.
- [evet] SGB ve PhishTank anahtarsız güncellendi.
- [evet] Anahtarı **kaydetmeden** uygulamayı kapatıp açtım; anahtar hatırlanmadı
      (beklenen davranış).
- [] Anahtarı açıkça kaydetmeyi seçtim; yeniden açınca hatırlandı.
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
