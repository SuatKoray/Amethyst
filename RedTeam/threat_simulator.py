import os
import time
import random
import string
from cryptography.fernet import Fernet

class AmethystSimulator:
    def __init__(self, log_directory="logs", base_filename="sys_cache_dat"):
        self.log_directory = log_directory
        self.base_filename = base_filename
        self.is_running = True
        os.makedirs(log_directory, exist_ok=True)
        self.encryption_key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.encryption_key)

    def _generate_dummy_data(self):
        # Entropi hesaplamasını güçlendirmek için veri boyutunu artırdık
        length = random.randint(50, 200) 
        dummy_text = ''.join(random.choices(string.ascii_letters + string.digits + " ", k=length))
        return f"[DUMMY_INPUT] {dummy_text}\n"

    def _get_dynamic_filepath(self):
        # Polimorfik Davranış: Statik imza tespitinden kaçmak için rastgele uzantılar
        ext = random.choice([".bin", ".dat", ".tmp", ".cache"])
        return os.path.join(self.log_directory, f"{self.base_filename}{ext}")

    def _encrypt_and_write(self, data):
        try:
            encrypted_data = self.cipher_suite.encrypt(data.encode('utf-8'))
            target_file = self._get_dynamic_filepath()
            with open(target_file, "ab") as f:
                f.write(encrypted_data + b"\n")
        except Exception as e:
            print(f"[HATA] Disk I/O işlemi başarısız: {e}")

    def start(self):
        print(f"[*] Project Amethyst - Kırmızı Takım (APT Modu) Başlatıldı.")
        print(f"[*] Kriptografik Motor: Aktif (AES-Fernet)")
        print(f"[*] Evasion (Gizlenme): Aktif (Jitter & Polymorphic I/O)")
        print(f"[*] Çıkmak için 'Ctrl+C' tuşlarına basın...\n")

        try:
            while self.is_running:
                dummy_data = self._generate_dummy_data()
                self._encrypt_and_write(dummy_data)
                
                # Jitter (Zaman Sapması): 1.5 ile 3.5 saniye arası rastgele bekleme
                sleep_time = random.uniform(1.5, 3.5)
                time.sleep(sleep_time)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        print("\n[!] Simülasyon sonlandırılıyor...")
        self.is_running = False

if __name__ == "__main__":
    # Log dizinini dinamik olarak bul
    target_directory = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
    simulator = AmethystSimulator(log_directory=target_directory)
    simulator.start()