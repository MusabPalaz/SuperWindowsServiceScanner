Windows Hizmet ve Güvenlik Günlüğü Kontrol Komut Dosyası
=================================================
Geliştiren: myp
Sürüm: 1.0
==================================================

**Unutmayın, Komut Dosyası size YARDIMCI olmak için oradadır, sonuçlara %100 GÜVENMEYİN!!!**

Komut dosyasını düzgün bir şekilde çalıştırmak için remotesigned'ı etkinleştirmeyi unutmayın. "Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process"
Ve kapatmak için "Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope Process"

Açıklama
--------
Bu betik, Windows işletim sisteminde çalışan hizmetleri ve güvenlik günlüklerini kontrol ederek sistemdeki şüpheli hizmetleri tespit etmeye yardımcı olur. Temel olarak aşağıdaki görevleri gerçekleştirir:

1. Yönetici Hakları Kontrolü:
- Betik çalıştırıldığında, gerekli yönetici haklarına sahip olup olmadığı kontrol edilir.
- Yönetici değilseniz, yönetici olarak tekrar çalıştırmanız istenebilir.

2. Hizmet Listesi Karşılaştırması:
- Kullanıcı tarafından sağlanan hizmet listesi (TXT, CSV veya JSON formatında) okunur.
- Sistemde çalışan hizmetler sağlanan liste ile karşılaştırılır. Listede olmayan hizmetler şüpheli olarak işaretlenir.

3. Güvenlik Günlüğü Sorgusu:

- Kullanıcının isteğine bağlı olarak, güvenlik günlükleri belirli Olay Kimlikleri (4697, 7030, 7031, 7045) üzerinden taranır.

- İlgili günlük kayıtları varsa, CSV formatında raporlanır.

4. Ek Sorgu Seçenekleri:
- Kullanıcı, şüpheli hizmetler hakkında ek araştırma yapmak için iki seçenekten birini seçebilir:

a) Google Arama: Şüpheli hizmet adları Google üzerinden aranır.

b) VirusTotal Tarama: Şüpheli hizmetlerin yürütülebilir dosyaları, kullanıcı tarafından sağlanan geçerli bir VirusTotal API anahtarı ile taranır.

- Bu işlemde, dosya yolundaki gereksiz argümanlar temizlenir ve doğru karma hesaplaması yapılır.

5. Günlük Kaydı:
- Tüm önemli adımlar, tespitler ve hata mesajları, betik dizinindeki "Service_Check_Log.txt" dosyasına kaydedilir.

Nasıl Çalıştırılır?
-------------------
1. Önkoşullar:
- PowerShell (Windows PowerShell veya PowerShell Core).
- Yönetici hakları (bazı işlemler için gereklidir).
- VirusTotal taraması yapılacaksa geçerli bir VirusTotal API anahtarı.

2. Komut Dosyasını Yükleme ve Çalıştırma:
- Komut dosyasını (örneğin, SuperWindowsServiceScanner.ps1) bilgisayarınıza kaydedin.
- PowerShell'i açın (mümkünse yönetici olarak).
- Komut dosyasının bulunduğu dizine geçin:
cd "Script Folder"
- Komut dosyasını şu komutla çalıştırın:
.\SuperWindowsServiceScanner.ps1
- Komut dosyası başladığında, ekrandaki talimatları izleyin ve gerekli bilgileri girin (örneğin, servis listesi dosyasının yolu, VirusTotal API anahtarı vb.).

3. Kullanıcı Etkileşimi:
- Yönetici hakları denetimi: Komut dosyasının yönetici haklarıyla çalışıp çalışmadığını kontrol eder. - Hizmet listesi dosya yolu: Sistemdeki hizmetler, sağlanan dosya yolu aracılığıyla belirtilen listeyle karşılaştırılır.

- Güvenlik günlüğü sorgusu: Günlükler, kullanıcı isteğine bağlı olarak belirli Olay Kimliklerine göre taranır ve raporlanır.

- Ek sorgu: Ek sorgu, Google arama veya VirusTotal tarama seçeneklerinden biri seçilerek gerçekleştirilir.

Amaç ve Hedefler
--------------------
Amaç:
- Windows hizmetlerini ve güvenlik günlüklerini kontrol ederek sistemdeki yetkisiz veya şüpheli hizmetleri tespit etmeye yardımcı olmak.
- Kullanıcılara ek güvenlik sağlamak amacıyla şüpheli hizmetler için ayrıntılı araştırma (Google ve VirusTotal entegrasyonu) sağlamak.

Hedefler:
- Sistem yöneticilerinin hizmetleri ve günlükleri inceleyerek olası güvenlik ihlallerini erken tespit etmelerini sağlamak.
- Kullanıcı tarafından sağlanan güvenilir hizmet listesiyle sistemdeki bilinmeyen veya yetkisiz hizmetleri tespit etmek.
- Şüpheli hizmetler hakkında otomatik raporlama ve harici kaynaklarla entegrasyon (VirusTotal) sağlamak.

Ek Bilgiler
------------
- Hizmet algılama sırasında, betik dosya yollarından gereksiz komut satırı argümanlarını temizleyerek doğru yürütülebilir yolu elde eder ve karma hesaplaması yapar.
- Tüm adımlar ve hata mesajları "Service_Check_Log.txt" dosyasına kaydedilir.
- Bu betik tam teşekküllü bir antivirüs çözümü değildir; sistemde ek bir kontrol ve bilgi aracıdır.

Uyarı
------
- Bu betik sistemde otomatik değişiklikler yapmaz, ancak algıladığı şüpheli hizmetler hakkında bilgi sağlar. Sonuçları değerlendirirken dikkatli olun!
- Kullanım tamamen kullanıcının kendi sorumluluğundadır! Herhangi bir işlem yapmadan önce sistem yedeğini almanız önerilir.
**Unutmayın, Betik size YARDIM etmek için oradadır, sonuçlara %100 GÜVENMEYİN!!!**







