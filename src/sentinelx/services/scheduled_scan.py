"""
Scheduled Scan Service: Run automatic scans at specified times.
"""

import threading
import schedule
import time
from pathlib import Path
from typing import Callable, Optional
from datetime import datetime

from sentinelx.utils.logger import get_logger

logger = get_logger(__name__)


class ScheduledScanService:
    """Run scheduled scans automatically."""
    
    def __init__(self, pipeline=None):
        self.pipeline = pipeline
        self.scheduler_thread = None
        self.running = False
        self.scheduled_jobs = []
        
        # Default scan schedule
        self.scan_times = {
            'hourly': '1:00',      # 1 hour from now, repeats
            'daily': '02:00',       # 2 AM daily
            'weekly': 'sunday_02:00'  # Sunday 2 AM
        }
    
    def start_scheduler(self):
        """Start the scheduler daemon."""
        if self.running:
            return
        
        self.running = True
        self.scheduler_thread = threading.Thread(target=self._run_scheduler, daemon=True)
        self.scheduler_thread.start()
        logger.info("[SCHEDULER] Scan scheduler started")
    
    def stop_scheduler(self):
        """Stop the scheduler."""
        self.running = False
        logger.info("[SCHEDULER] Scan scheduler stopped")
    
    def schedule_hourly_scan(self, scan_func: Callable, scan_path: str = None):
        """Schedule an hourly full system scan."""
        def run_scan():
            logger.info("[SCHEDULER] Running hourly scan...")
            if self.pipeline:
                self._run_pipeline_fullscan(scan_path)
            elif scan_func:
                scan_func()
        
        schedule.every().hour.do(run_scan)
        self.scheduled_jobs.append(('hourly', run_scan))
        logger.info("[SCHEDULER] Hourly scan scheduled")
    
    def schedule_daily_scan(self, scan_func: Callable, time_str: str = '02:00', scan_path: str = None):
        """Schedule a daily scan at specified time (HH:MM)."""
        def run_scan():
            logger.info(f"[SCHEDULER] Running daily scan at {time_str}...")
            if self.pipeline:
                self._run_pipeline_fullscan(scan_path)
            elif scan_func:
                scan_func()
        
        schedule.every().day.at(time_str).do(run_scan)
        self.scheduled_jobs.append(('daily', run_scan))
        logger.info(f"[SCHEDULER] Daily scan scheduled for {time_str}")
    
    def schedule_weekly_scan(self, scan_func: Callable, day: str = 'sunday', time_str: str = '02:00', scan_path: str = None):
        """Schedule a weekly scan (day: monday-sunday, time: HH:MM)."""
        def run_scan():
            logger.info(f"[SCHEDULER] Running weekly scan on {day} at {time_str}...")
            if self.pipeline:
                self._run_pipeline_fullscan(scan_path)
            elif scan_func:
                scan_func()
        
        day_mapping = {
            'monday': schedule.every().monday,
            'tuesday': schedule.every().tuesday,
            'wednesday': schedule.every().wednesday,
            'thursday': schedule.every().thursday,
            'friday': schedule.every().friday,
            'saturday': schedule.every().saturday,
            'sunday': schedule.every().sunday,
        }
        
        if day.lower() in day_mapping:
            day_mapping[day.lower()].at(time_str).do(run_scan)
            self.scheduled_jobs.append(('weekly', run_scan))
            logger.info(f"[SCHEDULER] Weekly scan scheduled for {day} at {time_str}")
    
    def schedule_custom_scan(self, interval_minutes: int, scan_func: Callable, scan_path: str = None):
        """Schedule a scan at custom interval (in minutes)."""
        def run_scan():
            logger.info(f"[SCHEDULER] Running custom interval scan ({interval_minutes} min)...")
            if self.pipeline:
                self._run_pipeline_fullscan(scan_path)
            elif scan_func:
                scan_func()
        
        schedule.every(interval_minutes).minutes.do(run_scan)
        self.scheduled_jobs.append(('custom', run_scan))
        logger.info(f"[SCHEDULER] Custom scan scheduled every {interval_minutes} minutes")
    
    def _run_pipeline_fullscan(self, scan_path: str = None):
        """Run full system scan via pipeline."""
        if not self.pipeline:
            return
        
        try:
            paths_to_scan = []
            
            if scan_path:
                paths_to_scan = [scan_path]
            else:
                # Default: scan common user directories
                paths_to_scan = [
                    str(Path.home() / 'Downloads'),
                    str(Path.home() / 'Desktop'),
                    str(Path.home() / 'Documents'),
                    'C:\\Program Files',
                    'C:\\Program Files (x86)',
                ]
            
            scan_time_start = datetime.now()
            threats_found = 0
            
            for path in paths_to_scan:
                path_obj = Path(path)
                if not path_obj.exists():
                    continue
                
                # Scan all files in directory
                for file_path in path_obj.rglob('*'):
                    if file_path.is_file():
                        try:
                            result = self.pipeline.scan_file(str(file_path))
                            if result and result.is_malicious:
                                threats_found += 1
                        except Exception as e:
                            logger.debug(f"[SCHEDULER] Error scanning file {file_path}: {str(e)}")
            
            elapsed = (datetime.now() - scan_time_start).total_seconds()
            logger.info(f"[SCHEDULER] Scan complete: {threats_found} threats found in {elapsed:.1f}s")
        
        except Exception as e:
            logger.error(f"[SCHEDULER] Error running scan: {str(e)}")
    
    def _run_scheduler(self):
        """Run the scheduler loop."""
        while self.running:
            try:
                schedule.run_pending()
                time.sleep(1)
            except Exception as e:
                logger.error(f"[SCHEDULER] Scheduler error: {str(e)}")
    
    def get_scheduled_jobs(self) -> list:
        """Get list of currently scheduled jobs."""
        return [(name, str(job)) for name, job in self.scheduled_jobs]
    
    def remove_all_jobs(self):
        """Remove all scheduled jobs."""
        schedule.clear()
        self.scheduled_jobs.clear()
        logger.info("[SCHEDULER] All scheduled jobs removed")
