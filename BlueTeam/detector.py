import os
import time
import json
import math
import psutil
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

def calculate_entropy(file_path):
    """Bir dosyanın Shannon Entropisini hesaplar."""
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
            
        if not data:
            return 0.0
            
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy
    except Exception:
        return 0.0

class FIMEventHandler(FileSystemEventHandler):
    def __init__(self, detector_engine):
        self.detector = detector_engine

    def on_modified(self, event):
        if not event.is_directory:
            self.detector.analyze_event(event.src_path)

class AmethystDetector:
    def __init__(self, watch_dir, alert_file="blue_team_alerts.json"):
        self.watch_dir = watch_dir
        self.alert_file = alert_file
        self.entropy_threshold = 6.5 
        self.processed_alerts = set()

    def analyze_event(self, filepath):
        current_entropy = calculate_entropy(filepath)
        
        # EĞİTİM VE İZLEME İÇİN CANLI LOG:
        print(f"[İZLEME] I/O Hareketi Algılandı! Güncel Entropi Skoru: {round(current_entropy, 3)} / 8.0")
        
        if current_entropy < self.entropy_threshold:
            return
            
        self._hunt_process(filepath, current_entropy)

    def _hunt_process(self, filepath, entropy):
        suspect_pid = None
        suspect_name = "Gizlenmiş_Süreç"
        
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    files = proc.open_files()
                    for f in files:
                        if os.path.abspath(f.path) == os.path.abspath(filepath):
                            suspect_pid = proc.info['pid']
                            suspect_name = proc.info['name']
                            break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                if suspect_pid:
                    break
        except Exception:
            pass

        self._generate_alert(filepath, suspect_pid, suspect_name, entropy)

    def _generate_alert(self, filepath, pid, name, entropy):
        alert_hash = f"{filepath}_{math.floor(time.time())}"
        if alert_hash in self.processed_alerts:
            return
        self.processed_alerts.add(alert_hash)

        alert_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "alert_type": "High_Entropy_IO_Detected",
            "severity": "CRITICAL",
            "details": {
                "target_file": filepath,
                "entropy_score": round(entropy, 2),
                "suspect_process": name,
                "suspect_pid": pid,
                "mitre_tactic": "TA0040 / T1486"
            }
        }
        
        with open(self.alert_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(alert_data) + "\n")
            
        print(f"\n[!!!] DEFANSİF ALARM: Kriptografik G/Ç İşlemi Yakalandı!")
        print(f"      Hedef Dosya   : {filepath}")
        print(f"      Entropi Skoru : {round(entropy, 2)} / 8.0 (Kritik)")
        print(f"      Şüpheli Süreç : {name} (PID: {pid})\n")

    def start(self):
        print(f"[*] Project Amethyst - Mavi Takım Motoru Başlatıldı.")
        print(f"[*] İzlenen Dizin: {self.watch_dir}")
        print(f"[*] Entropi Alarm Eşiği: {self.entropy_threshold}")
        print(f"[*] Kapatmak için 'Ctrl+C' tuşlarına basın...\n")
        
        os.makedirs(self.watch_dir, exist_ok=True)
        event_handler = FIMEventHandler(self)
        observer = Observer()
        observer.schedule(event_handler, self.watch_dir, recursive=False)
        observer.start()
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[!] Tespit motoru kapatılıyor...")
            observer.stop()
        observer.join()

if __name__ == "__main__":
    target_directory = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
    detector = AmethystDetector(watch_dir=target_directory)
    detector.start()