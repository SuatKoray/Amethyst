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
