import os
import time
import json
import math
import psutil
import hashlib
import yara
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
    except Exception: return 0.0

def get_file_hash(file_path):
    if not file_path or not os.path.exists(file_path): return "Bulunamadı"
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for block in iter(lambda: f.read(4096), b""): sha256.update(block)
        return sha256.hexdigest()
    except Exception: return "Erişim_Engellendi"

class FIMEventHandler(FileSystemEventHandler):
    def __init__(self, detector): self.detector = detector
    def on_modified(self, event):
        if not event.is_directory: self.detector.analyze_event(event.src_path)
    def on_created(self, event):
        if not event.is_directory: self.detector.analyze_event(event.src_path)

class AmethystDetector:
    def __init__(self, watch_dir, yara_rule_path, alert_file="blue_team_alerts.json"):
        self.watch_dir = watch_dir
        self.alert_file = alert_file
        self.entropy_threshold = 5.5
        self.processed_alerts = set()
        self.last_alert_time = {}
        
        # YARA Motorunu Derle ve Yükle
        self.yara_rules = None
        if os.path.exists(yara_rule_path):
            try:
                self.yara_rules = yara.compile(filepath=yara_rule_path)
                print(f"[*] YARA Motoru: Kurallar başarıyla yüklendi.")
            except Exception as e:
                print(f"[!] YARA Derleme Hatası: {e}")

    def analyze_event(self, filepath):
        time.sleep(0.1)
        
        current_entropy = calculate_entropy(filepath)
        
        # YARA Taraması
        yara_matches = []
        if self.yara_rules and os.path.exists(filepath):
            try:
                matches = self.yara_rules.match(filepath)
                yara_matches = [m.rule for m in matches]
            except Exception: pass

        # Entropi yüksekse VEYA YARA bir imza bulduysa avı başlat
        if current_entropy < self.entropy_threshold and not yara_matches: 
            return

        current_time = time.time()
        if filepath in self.last_alert_time and (current_time - self.last_alert_time[filepath]) < 2.0:
            return
        self.last_alert_time[filepath] = current_time

        self._hunt_process(filepath, current_entropy, yara_matches)

    def _hunt_process(self, filepath, entropy, yara_matches):
        suspect_pid, suspect_name, suspect_exe = None, "Gizlenmiş_Süreç", None
        network_info, action_taken = "Bağlantı_Yok / Yerel", "İzleniyor"
        target_filename = os.path.basename(filepath).lower()
        
        all_procs = list(psutil.process_iter(['pid', 'name', 'exe']))
        def risk_score(p):
            name = str(p.info.get('name', '')).lower()
            if any(risk in name for risk in ['python', 'powershell', 'cmd', 'java', 'ruby', 'node']): return 0
            return 1
        all_procs.sort(key=risk_score) 

        for proc in all_procs:
            try:
                if proc.info['name'] and proc.info['name'].lower() in [
                    'system', 'registry', 'svchost.exe', 'smss.exe', 
                    'csrss.exe', 'lsass.exe', 'services.exe', 'wininit.exe', 'explorer.exe'
                ]: continue
                    
                files = proc.open_files()
                for f in files:
                    if os.path.basename(f.path).lower() == target_filename:
                        suspect_pid = proc.info['pid']
                        suspect_name = proc.info['name']
                        suspect_exe = proc.info.get('exe', 'Bulunamadı')
                        try:
                            conns = proc.net_connections(kind='inet')
                            if conns:
                                remote_ip = conns[0].raddr.ip if conns[0].raddr else "Bilinmiyor"
                                remote_port = conns[0].raddr.port if conns[0].raddr else "Bilinmiyor"
                                network_info = f"{remote_ip}:{remote_port}"
                        except Exception: network_info = "Erişim_Engellendi"

                        try:
                            proc.kill()
                            action_taken = "SÜREÇ ÖLDÜRÜLDÜ (Terminated)"
                        except Exception: action_taken = "Öldürme Başarısız (Yönetici İzni Gerekli)"
                        break
            except Exception: continue
            if suspect_pid: break

        suspect_hash = get_file_hash(suspect_exe)
        self._generate_alert(filepath, suspect_pid, suspect_name, suspect_hash, network_info, action_taken, entropy, yara_matches)

    def _generate_alert(self, filepath, pid, name, process_hash, net_info, action, entropy, yara_matches):
        alert_hash = f"{filepath}_{math.floor(time.time() / 2)}"
        if alert_hash in self.processed_alerts: return
        self.processed_alerts.add(alert_hash)

        yara_str = ", ".join(yara_matches) if yara_matches else "Temiz (Sadece Davranışsal Analiz)"

        alert_data = {
            "@timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "event": {
                "kind": "alert", "category": ["malware", "intrusion_detection"],
                "type": ["info"], "action": action, "severity": 90, "module": "amethyst_edr"
            },
            "threat": {
                "technique": {"id": "T1486", "name": "Data Encrypted for Impact"},
                "indicator": {"type": "file", "yara_signatures": yara_matches, "file": {"hash": {"sha256": process_hash}}}
            },
            "process": {"pid": pid, "name": name, "executable": name},
            "file": {
                "path": filepath, "extension": os.path.splitext(filepath)[1].replace(".", ""),
                "attributes": {"shannon_entropy": round(entropy, 2)}
            },
            "network": {
                "direction": "outbound", "destination": {"address": net_info.split(":")[0] if ":" in net_info else "local"}
            }
        }
        
        with open(self.alert_file, "a", encoding="utf-8") as f: f.write(json.dumps(alert_data) + "\n")
        
        print(f"\n[!!!] DEFANSİF ALARM: Şifreleme İşlemi Yakalandı!")
        print(f"      Hedef Dosya    : {filepath}\n      Entropi Skoru  : {round(entropy, 2)} / 8.0")
        print(f"      YARA Eşleşmesi : {yara_str}")
        print(f"      Şüpheli Süreç  : {name} (PID: {pid})\n      Adli Hash      : {process_hash}")
        print(f"      EDR Müdahalesi : {action}")

if __name__ == "__main__":
    print(f"[*] Project Amethyst - Mavi Takım Motoru Başlatıldı.")
    print(f"[*] Mimari Güncelleme: HİBRİT EDR (Davranışsal Entropi + Statik YARA) Aktif")
    print(f"[*] Loglama: SIEM / Elastic Common Schema (ECS) Formatı Aktif\n")
    
    target_directory = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
    yara_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules", "ransomware.yar")
    
    detector = AmethystDetector(watch_dir=target_directory, yara_rule_path=yara_path)
    
    os.makedirs(detector.watch_dir, exist_ok=True)
    observer = Observer()
    observer.schedule(FIMEventHandler(detector), detector.watch_dir, recursive=False)
    observer.start()
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Tespit motoru kapatılıyor...")
        observer.stop()
    observer.join()