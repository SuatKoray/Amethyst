rule Fernet_Ransomware_Payload
{
    meta:
        author = "Amethyst Blue Team"
        description = "Detects files encrypted with Python Cryptography Fernet module"
        threat_level = "Critical"
        mitre_technique = "T1486"
    
    strings:
        // Fernet token'larının karakteristik başlangıç başlığı
        $fernet_header = "gAAAAA" ascii
        
    condition:
        $fernet_header
}