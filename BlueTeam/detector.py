import os
import time
import json
import math
import psutil
import hashlib
from datetime import datetime, timezone
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

def calculate_entropy(file_path):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        if not data: return 0.0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0: entropy += - p_x * math.log(p_x, 2)
        return entropy
    except Exception:
        return 0.0

def get_file_hash(file_path):
    if not file_path or not os.path.exists(file_path):
        return "Bulunamadı"
    try:
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return "Erişim_Engellendi"

class FIMEventHandler(FileSystemEventHandler):
    def __init__(self, detector_engine):
        self.detector = detector_engine

    def on_modified(self, event):
        if not event.is_directory:
            self.detector.analyze_event(event.src_path)
            
    def on_created(self, event):
        if not event.is_directory:
            self.detector.analyze_event(event.src_path)

class AmethystDetector:
    def __init__(self, watch_dir, alert_file="blue_team_alerts.json"):
        self.watch_dir = watch_dir
        self.alert_file = alert_file
        self.entropy_threshold = 5.5 
        self.processed_alerts = set()

    def analyze_event(self, filepath):
        current_entropy = calculate_entropy(filepath)
        if current_entropy < self.entropy_threshold:
            return
        self._hunt_process(filepath, current_entropy)

    def _hunt_process(self, filepath, entropy):
        suspect_pid = None
        suspect_name = "Gizlenmiş_Süreç"
        suspect_exe = None
        network_info = "Bağlantı_Yok / Yerel"
        action_taken = "İzleniyor"
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    files = proc.open_files()
                    for f in files:
                        if os.path.abspath(f.path) == os.path.abspath(filepath):
                            suspect_pid = proc.info['pid']
                            suspect_name = proc.info['name']
                            suspect_exe = proc.info['exe']
                            
                            # 1. AĞ AVI (C2 Tespiti): Sürecin o anki TCP/IP bağlantılarını çek
                            try:
                                conns = proc.connections(kind='inet')
                                if conns:
                                    remote_ip = conns[0].raddr.ip if conns[0].raddr else "Bilinmiyor"
                                    remote_port = conns[0].raddr.port if conns[0].raddr else "Bilinmiyor"
                                    network_info = f"{remote_ip}:{remote_port}"
                            except psutil.AccessDenied:
                                network_info = "Erişim_Engellendi"

                            # 2. AKTİF MÜDAHALE (Kill Switch): Zararlının kafasını kopar!
                            try:
                                proc.kill()
                                action_taken = "SÜREÇ ÖLDÜRÜLDÜ (Terminated)"
                            except psutil.AccessDenied:
                                action_taken = "Öldürme Başarısız (Yönetici İzni Gerekli)"
                            
                            break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                if suspect_pid:
                    break
        except Exception:
            pass

        suspect_hash = get_file_hash(suspect_exe)
        self._generate_alert(filepath, suspect_pid, suspect_name, suspect_hash, network_info, action_taken, entropy)

    def _generate_alert(self, filepath, pid, name, process_hash, net_info, action, entropy):
        alert_hash = f"{filepath}_{math.floor(time.time() / 2)}"
        if alert_hash in self.processed_alerts:
            return
        self.processed_alerts.add(alert_hash)

        alert_data = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "alert_type": "Ransomware_Behavior_Detected",
            "severity": "CRITICAL",
            "details": {
                "target_file": filepath,
                "entropy_score": round(entropy, 2),
                "suspect_process": name,
                "suspect_pid": pid,
                "process_sha256": process_hash,
                "network_c2": net_info,
                "edr_action": action,
                "mitre_tactic": "TA0040 / T1486"
            }
        }
        
        with open(self.alert_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(alert_data) + "\n")
            
        print(f"\n[!!!] DEFANSİF ALARM: Şifreleme İşlemi (Ransomware) Yakalandı!")
        print(f"      Hedef Dosya    : {filepath}")
        print(f"      Entropi Skoru  : {round(entropy, 2)} / 8.0")
        print(f"      Şüpheli Süreç  : {name} (PID: {pid})")
        print(f"      Adli Hash      : {process_hash}")
        print(f"      Ağ Bağlantısı  : {net_info}")
        print(f"      EDR Müdahalesi : {action}")

    def start(self):
        print(f"[*] Project Amethyst - Mavi Takım Motoru Başlatıldı.")
        print(f"[*] İzlenen Dizin: {self.watch_dir}")
        print(f"[*] Entropi Alarm Eşiği: {self.entropy_threshold}")
        print(f"[*] Adli Bilişim: SHA-256 Hashing ve TCP/IP Ağ Taraması Aktif")
        print(f"[*] Aktif Müdahale: Zararlı Süreçleri Otomatik Öldürme (Kill-Switch) Aktif")
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