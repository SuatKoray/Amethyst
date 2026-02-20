import os
import time
import random
import string
from cryptography.fernet import Fernet

class AmethystSimulator:
    def __init__(self, log_directory="logs", filename="sys_cache_dat.bin", interval=2):
        """
        Kriptografik Davranış Simülatörünü başlatır.
        :param log_directory: Dosyanın yazılacağı klasör
        :param filename: Şüphe çekmeyecek sahte cache dosya adı (Anti-Forensics)
        :param interval: Sahte veri üretme ve diske yazma sıklığı (saniye)
        """
        self.log_path = os.path.join(log_directory, filename)
        self.interval = interval
        self.is_running = True
        
        # Log klasörü yoksa güvenli bir şekilde oluştur
        os.makedirs(log_directory, exist_ok=True)
        
        # Enterprise Standart: Fernet (AES tabanlı) için dinamik anahtar üretimi
        self.encryption_key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.encryption_key)

    def _generate_dummy_data(self):
        """
        Gerçek klavye verisi yerine, rastgele karakterlerden oluşan
        sahte bir metin bloğu üretir. (Etik ve güvenli simülasyon)
        """
        length = random.randint(15, 50) # 15-50 karakter arası rastgele tuş vuruşu simülasyonu
        dummy_text = ''.join(random.choices(string.ascii_letters + string.digits + " ", k=length))
        return f"[DUMMY_INPUT] {dummy_text}\n"

    def _encrypt_and_write(self, data):
        """
        Üretilen veriyi şifreler ve yüksek entropili (karmaşık) bir şekilde diske yazar.
        Blue Team FIM (Dosya Bütünlük İzleme) motorunu test etmek için kritik bir adımdır.
        """
        try:
            # Veriyi byte formatına çevir ve şifrele
            encrypted_data = self.cipher_suite.encrypt(data.encode('utf-8'))
            
            # 'ab' (append binary) modunda dosyaya ekle. Şifreli veri binary'dir.
            with open(self.log_path, "ab") as f:
                f.write(encrypted_data + b"\n")
        except Exception as e:
            # Fail-safe mekanizması: Programın çökmesini engeller
            print(f"[HATA] Şifreleme veya disk I/O işlemi başarısız: {e}")

    def start(self):
        """
        Simülatörü başlatır ve periyodik I/O döngüsüne girer.
        """
        print(f"[*] Project Amethyst - Kırmızı Takım Simülatörü Başlatıldı.")
        print(f"[*] Kriptografik Motor: Aktif (AES-Fernet)")
        print(f"[*] Hedef Dosya: {self.log_path}")
        print(f"[*] Üretilen Şifreleme Anahtarı (Analiz için): {self.encryption_key.decode('utf-8')}")
        print(f"[*] Çıkmak için 'Ctrl+C' tuşlarına basın...\n")

        try:
            while self.is_running:
                # 1. Sahte veri üret
                dummy_data = self._generate_dummy_data()
                
                # 2. Şifrele ve diske yaz (Mavi Takım aracını tetikleyecek hareket)
                self._encrypt_and_write(dummy_data)
                
                # 3. Belirlenen süre kadar bekle (I/O Optimizasyonu)
                time.sleep(self.interval)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        """
        Güvenli çıkış (Graceful Shutdown)
        """
        print("\n[!] Kullanıcı tarafından manuel kesinti algılandı. Simülasyon sonlandırılıyor...")
        self.is_running = False

if __name__ == "__main__":
    # Simülatörü 2 saniyede bir gizli I/O işlemi yapacak şekilde başlatıyoruz.
    # Bu sıklık, Blue Team aracımızın davranışsal analiz eşiğini aşması için idealdir.
    simulator = AmethystSimulator(interval=2)
    simulator.start()