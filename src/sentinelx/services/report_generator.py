"""
Report Generation Service: Generate detailed scan and security reports.
"""

import json
import csv
from pathlib import Path
from typing import List, Dict
from datetime import datetime
from dataclasses import asdict

from sentinelx.utils.logger import get_logger

logger = get_logger(__name__)


class ReportGenerator:
    """Generate comprehensive security and scan reports."""
    
    REPORT_DIR = Path('logs/reports')
    
    def __init__(self):
        self.REPORT_DIR.mkdir(parents=True, exist_ok=True)
    
    def generate_scan_report(self, scan_results: List, scan_type: str = 'manual') -> str:
        """Generate scan report in JSON and CSV formats."""
        timestamp = datetime.now().isoformat('_').replace(':', '-')
        
        # Count results
        total_files = len(scan_results)
        malicious = sum(1 for r in scan_results if hasattr(r, 'is_malicious') and r.is_malicious)
        suspicious = sum(1 for r in scan_results if hasattr(r, 'is_malicious') and not r.is_malicious and hasattr(r, 'heuristics_flagged') and r.heuristics_flagged)
        
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'scan_type': scan_type,
            'summary': {
                'total_files_scanned': total_files,
                'malicious_files': malicious,
                'suspicious_files': suspicious,
                'clean_files': total_files - malicious - suspicious,
                'threat_percentage': f"{(malicious / total_files * 100):.2f}%" if total_files > 0 else "0%"
            },
            'details': []
        }
        
        # Add detailed results
        for result in scan_results:
            try:
                detail = {
                    'file_path': getattr(result, 'file_path', 'unknown'),
                    'file_size': getattr(result, 'file_size', 0),
                    'is_malicious': getattr(result, 'is_malicious', False),
                    'threat_type': getattr(result, 'threat_type', 'unknown'),
                    'severity': getattr(result, 'severity', 'unknown'),
                    'ai_score': getattr(result, 'ml_score', 0),
                    'heuristics_score': getattr(result, 'heuristics_score', 0),
                    'yara_matches': getattr(result, 'yara_matches', []),
                    'scan_time': str(getattr(result, 'scan_time', 'unknown'))
                }
                report_data['details'].append(detail)
            except Exception as e:
                logger.debug(f"[REPORT] Error processing result: {str(e)}")
        
        # Save JSON report
        json_file = self.REPORT_DIR / f"scan_report_{scan_type}_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        # Save CSV report
        csv_file = self.REPORT_DIR / f"scan_report_{scan_type}_{timestamp}.csv"
        with open(csv_file, 'w', newline='') as f:
            if report_data['details']:
                writer = csv.DictWriter(f, fieldnames=report_data['details'][0].keys())
                writer.writeheader()
                writer.writerows(report_data['details'])
        
        logger.info(f"[REPORT] Scan report generated: {json_file}")
        return str(json_file)
    
    def generate_security_report(self, threats_data: Dict) -> str:
        """Generate comprehensive security report."""
        timestamp = datetime.now().isoformat('_').replace(':', '-')
        
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'report_type': 'security',
            'system_overview': {
                'total_threats_detected': threats_data.get('total_threats', 0),
                'network_threats': threats_data.get('network_threats', 0),
                'process_threats': threats_data.get('process_threats', 0),
                'file_threats': threats_data.get('file_threats', 0),
            },
            'threat_breakdown': {
                'by_type': threats_data.get('by_type', {}),
                'by_severity': threats_data.get('by_severity', {}),
            },
            'network_status': threats_data.get('network_status', {}),
            'protection_status': threats_data.get('protection_status', {}),
            'recommendations': self._generate_recommendations(threats_data)
        }
        
        json_file = self.REPORT_DIR / f"security_report_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        logger.info(f"[REPORT] Security report generated: {json_file}")
        return str(json_file)
    
    def generate_threat_intelligence_report(self, iocs: Dict) -> str:
        """Generate threat intelligence indicators report."""
        timestamp = datetime.now().isoformat('_').replace(':', '-')
        
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'report_type': 'threat_intelligence',
            'indicators_of_compromise': {
                'malicious_files': iocs.get('files', []),
                'malicious_ips': iocs.get('ips', []),
                'malicious_domains': iocs.get('domains', []),
                'malicious_urls': iocs.get('urls', []),
                'process_hashes': iocs.get('process_hashes', []),
                'registry_keys': iocs.get('registry_keys', []),
            },
            'statistics': {
                'unique_malware_families': iocs.get('malware_families', 0),
                'unique_threat_actors': iocs.get('threat_actors', 0),
                'total_indicators': len(iocs.get('files', [])) + len(iocs.get('ips', [])) + len(iocs.get('domains', []))
            }
        }
        
        json_file = self.REPORT_DIR / f"threat_intelligence_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        logger.info(f"[REPORT] Threat intelligence report generated: {json_file}")
        return str(json_file)
    
    def generate_quarantine_report(self, quarantine_entries: List) -> str:
        """Generate quarantine status report."""
        timestamp = datetime.now().isoformat('_').replace(':', '-')
        
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'report_type': 'quarantine',
            'summary': {
                'total_quarantined_files': len(quarantine_entries),
                'by_severity': {},
                'by_type': {}
            },
            'quarantined_files': []
        }
        
        for entry in quarantine_entries:
            try:
                entry_dict = asdict(entry) if hasattr(entry, '__dataclass_fields__') else entry
                report_data['quarantined_files'].append(entry_dict)
                
                severity = entry_dict.get('severity', 'unknown')
                threat_type = entry_dict.get('threat_type', 'unknown')
                
                report_data['summary']['by_severity'][severity] = report_data['summary']['by_severity'].get(severity, 0) + 1
                report_data['summary']['by_type'][threat_type] = report_data['summary']['by_type'].get(threat_type, 0) + 1
            
            except Exception as e:
                logger.debug(f"[REPORT] Error processing quarantine entry: {str(e)}")
        
        json_file = self.REPORT_DIR / f"quarantine_report_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        logger.info(f"[REPORT] Quarantine report generated: {json_file}")
        return str(json_file)
    
    def _generate_recommendations(self, threats_data: Dict) -> List[str]:
        """Generate security recommendations based on threats."""
        recommendations = [
            "Keep Windows and all software updated with latest patches",
            "Run regular full system scans (at least weekly)",
            "Enable Windows Defender or equivalent antivirus",
            "Use strong, unique passwords with MFA where available",
            "Avoid downloading files from untrusted sources",
            "Disable unnecessary network services and ports",
            "Monitor system logs for suspicious activity"
        ]
        
        # Add specific recommendations based on threats
        if threats_data.get('network_threats', 0) > 0:
            recommendations.append("Review firewall rules and network configurations immediately")
            recommendations.append("Check for unauthorized network connections and services")
        
        if threats_data.get('process_threats', 0) > 0:
            recommendations.append("Investigate suspicious processes and consider system restoration")
            recommendations.append("Review process startup locations and command-line arguments")
        
        if threats_data.get('file_threats', 0) > 0:
            recommendations.append("Quarantine detected malware and use recovery tools if needed")
            recommendations.append("Scan external drives and backup storage")
        
        return recommendations
    
    def get_report_list(self) -> List[str]:
        """Get list of generated reports."""
        try:
            reports = list(self.REPORT_DIR.glob('*.json'))
            return [str(r) for r in sorted(reports, reverse=True)]
        except Exception as e:
            logger.error(f"[REPORT] Error listing reports: {str(e)}")
            return []
    
    def cleanup_old_reports(self, days: int = 30):
        """Remove reports older than specified days."""
        try:
            from datetime import timedelta
            cutoff = datetime.now() - timedelta(days=days)
            
            for report_file in self.REPORT_DIR.glob('*.json'):
                if datetime.fromtimestamp(report_file.stat().st_mtime) < cutoff:
                    report_file.unlink()
                    logger.info(f"[REPORT] Cleaned old report: {report_file.name}")
        
        except Exception as e:
            logger.error(f"[REPORT] Error cleaning reports: {str(e)}")
