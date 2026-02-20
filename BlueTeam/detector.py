import os
import time
import json
import psutil
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class SuspiciousActivityHandler(FileSystemEventHandler):
    """
    Watchdog kütüphanesi için dosya sistemi olay dinleyicisi.
    Sadece dosya değişiklik (FIM - File Integrity Monitoring) olaylarını yakalar.
    """
    def __init__(self, detector_engine):
        self.detector = detector_engine

    def on_modified(self, event):
        # Klasör değişikliklerini yoksay, sadece dosyalara odaklan
        if not event.is_directory:
            self.detector.analyze_file_event(event.src_path)

class AmethystDetector:
    def __init__(self, target_dir, alert_log_path="blue_team_alerts.json"):
        """
        Tespit motorunu başlatır.
        :param target_dir: İzlenecek hedef dizin (Örn: RedTeam loglarının olduğu yer)
        :param alert_log_path: Tespit edilen anomalilerin yazılacağı JSON log dosyası
        """
        self.target_dir = target_dir
        self.alert_log_path = alert_log_path
        self.file_mod_tracker = {}
        self.risk_threshold = 50  # Risk skoru bu değeri aşarsa alarm üretilir

    def analyze_file_event(self, filepath):
        """
        Dosya değişiklik frekansını analiz eder (Davranışsal Heuristic Analiz).
        Bir dosya kısa süre içinde sürekli güncelleniyorsa, bu bir keylogger veya ransomware işaretidir.
        """
        now = time.time()
        
        # Dosya takibi için listeyi başlat
        if filepath not in self.file_mod_tracker:
            self.file_mod_tracker[filepath] = []
        
        # Sadece son 10 saniye içindeki olayları hafızada tut (Performans Optimizasyonu)
        self.file_mod_tracker[filepath] = [t for t in self.file_mod_tracker[filepath] if now - t < 10]
        self.file_mod_tracker[filepath].append(now)

        # KURAL: Eğer bir dosya 10 saniye içinde 3'ten fazla kez modifiye edildiyse, şüphelidir!
        # (Aşama 1'deki RedTeam aracımız her buffer dolduğunda yazma yapıyor, bunu yakalayacağız)
        if len(self.file_mod_tracker[filepath]) > 3:
            self._trigger_investigation(filepath)
            # Alarm spam'ini önlemek için sayacı sıfırla
            self.file_mod_tracker[filepath] = []

    def _trigger_investigation(self, filepath):
        """
        Anomali tespit edildiğinde, işletim sistemi süreçlerini (Process) tarayarak
        bu dosyayı hangi uygulamanın kullandığını bulur.
        """
        suspect_pid = None
        suspect_name = "Bilinmiyor"
        
        try:
            # Sistemdeki tüm süreçleri PID ve İsimleriyle getir
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    # Sürecin o an açık tuttuğu dosyaları (file handles) kontrol et
                    files = proc.open_files()
                    for f in files:
                        if os.path.abspath(f.path) == os.path.abspath(filepath):
                            suspect_pid = proc.info['pid']
                            suspect_name = proc.info['name']
                            break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    # İşletim sistemi veya yetki sınırlarına takılan süreçleri sessizce atla
                    continue
                
                if suspect_pid:
                    break
        except Exception as e:
            print(f"[!] Süreç taraması sırasında hata: {e}")

        # Risk Skorlama Mantığı
        # Eğer dosyaya yazan süreci bulabildiysek, bu kesin bir tehdittir (Score: 80)
        # Sadece dosya değişiyorsa ama süreç gizlenmişse/bulunamadıysa (Score: 40)
        score = 80 if suspect_pid else 40
        
        self._generate_alert(filepath, suspect_pid, suspect_name, score)

    def _generate_alert(self, filepath, pid, name, score):
        """
        Log analizi ve SIEM araçları için yapılandırılmış JSON formatında alarm üretir.
        """
        severity = "KRİTİK" if score >= self.risk_threshold else "UYARI"
        
        alert_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "alert_type": "Suspicious_IO_Activity",
            "severity": severity,
            "risk_score": score,
            "details": {
                "target_file": filepath,
                "suspect_process_name": name,
                "suspect_pid": pid,
                "mitre_attck_tactic": "TA0009 - Collection / T1056 - Input Capture"
            }
        }
        
        # Log dosyasına JSON satırı olarak yaz (JSONL formatı log analizörleri için idealdir)
        try:
            with open(self.alert_log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(alert_data) + "\n")
        except Exception as e:
            print(f"[HATA] Log yazılamadı: {e}")

        # Konsol Çıktısı (Eğitim/Görselleştirme için)
        print(f"\n[!] DEFANSİF ALARM: {severity} - Risk Skoru: {score}")
        print(f"    Hedef Dosya : {filepath}")
        print(f"    Şüpheli Süreç: {name} (PID: {pid})")
        print(f"    Log Kaydedildi: {self.alert_log_path}")

    def start(self):
        """
        Dosya sistemi izleyicisini (Observer) arka planda asenkron olarak başlatır.
        """
        event_handler = SuspiciousActivityHandler(self)
        observer = Observer()
        observer.schedule(event_handler, self.target_dir, recursive=True)
        observer.start()
        
        print(f"[*] Project Amethyst - Mavi Takım Motoru Başlatıldı.")
        print(f"[*] İzlenen Dizin: {self.target_dir}")
        print(f"[*] Kapatmak için 'Ctrl+C' tuşlarına basın...\n")
        
        try:
            # Ana thread'i açık tut
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[!] Tespit motoru kapatılıyor...")
            observer.stop()
        observer.join()

if __name__ == "__main__":
    # RedTeam'in log yazdığı klasörün bir üst dizinini veya direkt log klasörünü izleyebiliriz.
    # Çalışma dizinine göre yolu ayarlıyoruz.
    target_directory = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "RedTeam", "logs")
    
    # İzlenecek klasör yoksa oluştur (Hata almamak için)
    os.makedirs(target_directory, exist_ok=True)
    
    detector = AmethystDetector(target_dir=target_directory)
    detector.start()