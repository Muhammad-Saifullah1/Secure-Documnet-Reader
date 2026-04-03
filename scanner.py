import re
import math
import magic

# Blacklisted extensions
BLACKLIST_EXT = {'.exe', '.bat', '.cmd', '.sh', '.dll', '.msi', '.vbs', '.ps1'}

DANGEROUS_REGEX = [
    rb'eval\s*\(', rb'exec\s*\(', rb'shell_exec\s*\(', 
    rb'system\s*\(', rb'base64_decode\s*\(', rb'<script>',
    rb'WScript\.Shell', rb'CreateObject', rb'cmd\.exe'
]

def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(bytes([x]))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def check_magic_bytes(data):
    try:
        return magic.from_buffer(data)
    except Exception:
        return "Unknown"

def run_security_scan(filename, extension, raw_bytes):
    """
    Phase 2: Rule-based security checks
    """
    threats = []
    warnings = []
    
    # Check 1: Extension blacklist check
    if extension.lower() in BLACKLIST_EXT:
        threats.append(f"Blacklisted extension detected: {extension}")
        
    # Check 2: Content type signature check via magic library
    file_type = check_magic_bytes(raw_bytes)
    
    # Check 3: Extension vs actual type mismatch
    file_type_lower = file_type.lower()
    is_windows_exe = 'ms-dos executable' in file_type_lower or 'pe32 executable' in file_type_lower
    is_linux_elf = 'elf' in file_type_lower and 'executable' in file_type_lower
    
    if is_windows_exe and extension.lower() != '.exe':
        threats.append(f"Content indicates an Executable, but extension is {extension}")
    elif is_linux_elf:
        threats.append("ELF Linux executable detected.")
        
    # Check 4: Regex pattern scan
    for pattern in DANGEROUS_REGEX:
        if re.search(pattern, raw_bytes, re.IGNORECASE):
            threats.append(f"Dangerous pattern detected: {pattern.decode(errors='ignore')}")
            
    # Check 5: Entropy analysis
    entropy = calculate_entropy(raw_bytes)
    if entropy > 7.5:
        warnings.append(f"High entropy ({entropy:.2f}) detected, possibly obfuscated content.")
        
    # Check 6: Binary content in text file
    if extension.lower() in ['.txt', '.csv', '.json', '.xml', '.html', '.md']:
        # Basic check for null bytes which shouldn't be in text formats generally
        if b'\x00' in raw_bytes[:1024]:
            threats.append(f"Binary content (null bytes) detected in a {extension} text format file.")
            
    return {
        "threats": threats,
        "warnings": warnings,
        "safe": len(threats) == 0
    }
