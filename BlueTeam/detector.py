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
