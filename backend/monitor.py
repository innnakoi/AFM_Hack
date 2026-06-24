import psutil
import threading
from datetime import datetime
from typing import List, Dict
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ProcessMonitor:
    """Monitor running processes"""
    
    @staticmethod
    def get_processes() -> List[Dict]:
        """Get list of running processes with details"""
        processes = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time']):
                try:
                    pinfo = proc.as_dict(attrs=['pid', 'name', 'exe', 'cmdline', 'create_time'])
                    pinfo['cpu_percent'] = proc.cpu_percent(interval=None)
                    pinfo['memory_percent'] = proc.memory_percent()
                    processes.append(pinfo)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as e:
            logger.error(f"Error monitoring processes: {e}")
        
        return processes
    
    @staticmethod
    def get_process_details(pid: int) -> Dict:
        """Get detailed information about a specific process"""
        try:
            proc = psutil.Process(pid)
            return {
                'pid': pid,
                'name': proc.name(),
                'exe': proc.exe(),
                'cmdline': proc.cmdline(),
                'status': proc.status(),
                'create_time': datetime.fromtimestamp(proc.create_time()),
                'cpu_percent': proc.cpu_percent(interval=0.1),
                'memory_info': proc.memory_info()._asdict(),
                'num_threads': proc.num_threads(),
                'connections': len(proc.connections()),
            }
        except Exception as e:
            logger.error(f"Error getting process details: {e}")
            return {}


class FileMonitor(FileSystemEventHandler):
    """Monitor file system activity"""
    
    def __init__(self, callback=None):
        self.callback = callback
        self.file_events = []
    
    def on_created(self, event):
        if not event.is_directory:
            self.file_events.append({
                'type': 'created',
                'path': event.src_path,
                'timestamp': datetime.now()
            })
            if self.callback:
                self.callback('created', event.src_path)
    
    def on_modified(self, event):
        if not event.is_directory:
            self.file_events.append({
                'type': 'modified',
                'path': event.src_path,
                'timestamp': datetime.now()
            })
            if self.callback:
                self.callback('modified', event.src_path)
    
    def on_deleted(self, event):
        if not event.is_directory:
            self.file_events.append({
                'type': 'deleted',
                'path': event.src_path,
                'timestamp': datetime.now()
            })
            if self.callback:
                self.callback('deleted', event.src_path)


class NetworkMonitor:
    """Monitor network connections"""
    
    @staticmethod
    def get_connections() -> List[Dict]:
        """Get active network connections"""
        connections = []
        try:
            for conn in psutil.net_connections():
                try:
                    proc = psutil.Process(conn.pid) if conn.pid else None
                    connections.append({
                        'pid': conn.pid,
                        'process': proc.name() if proc else 'Unknown',
                        'status': conn.status,
                        'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        'type': conn.type,
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as e:
            logger.error(f"Error monitoring network: {e}")
        
        return connections
    
    @staticmethod
    def get_suspicious_ips() -> List[str]:
        """Get list of potentially suspicious IPs"""
        known_malicious = [
            '192.0.2.0',  # TEST-NET-1
            '198.51.100.0',  # TEST-NET-2
            '203.0.113.0',  # TEST-NET-3
        ]
        connections = NetworkMonitor.get_connections()
        suspicious = []
        
        for conn in connections:
            if conn['remote_addr']:
                ip = conn['remote_addr'].split(':')[0]
                if ip in known_malicious:
                    suspicious.append(ip)
        
        return suspicious


class SystemMetrics:
    """Collect system resource metrics"""
    
    @staticmethod
    def get_metrics() -> Dict:
        """Get current system metrics"""
        return {
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory': {
                'total': psutil.virtual_memory().total,
                'available': psutil.virtual_memory().available,
                'percent': psutil.virtual_memory().percent,
                'used': psutil.virtual_memory().used,
            },
            'disk': {
                'total': psutil.disk_usage('/').total,
                'used': psutil.disk_usage('/').used,
                'free': psutil.disk_usage('/').free,
                'percent': psutil.disk_usage('/').percent,
            },
            'timestamp': datetime.now()
        }


class MonitoringService:
    """Unified monitoring service"""
    
    def __init__(self):
        self.process_monitor = ProcessMonitor()
        self.file_monitor = FileMonitor()
        self.network_monitor = NetworkMonitor()
        self.metrics = SystemMetrics()
        self.observer = None
    
    def start_file_monitoring(self, path: str = '/'):
        """Start monitoring file system"""
        try:
            self.observer = Observer()
            self.observer.schedule(self.file_monitor, path, recursive=True)
            self.observer.start()
            logger.info(f"File monitoring started for {path}")
        except Exception as e:
            logger.error(f"Error starting file monitoring: {e}")
    
    def stop_file_monitoring(self):
        """Stop monitoring file system"""
        if self.observer:
            self.observer.stop()
            self.observer.join()
            logger.info("File monitoring stopped")
    
    def collect_all_data(self) -> Dict:
        """Collect all monitoring data"""
        return {
            'processes': self.process_monitor.get_processes(),
            'connections': self.network_monitor.get_connections(),
            'metrics': self.metrics.get_metrics(),
            'timestamp': datetime.now()
        }
