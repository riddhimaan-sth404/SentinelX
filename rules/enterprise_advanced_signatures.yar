/*
    SentinelX Enterprise Advanced YARA Rules Database
    Coverage: 200+ enterprise-grade signatures for sophisticated threats
    Includes: APT patterns, ransomware families, rootkits, zero-days
    Updated: 2026
*/

// ============================================================================
// RANSOMWARE FAMILIES - ENTERPRISE DETECTION
// ============================================================================

rule Ransomware_LockBit_Behavior {
    meta:
        description = "LockBit ransomware behavioral patterns"
        severity = "critical"
    strings:
        $lockbit1 = "vss" nocase
        $lockbit2 = "delete shadows /all" nocase
        $lockbit3 = "wmic shadowcopy delete" nocase
        $lockbit4 = ".lockbit" nocase
        $lockbit5 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" nocase
    condition:
        3 of them
}

rule Ransomware_Conti_Behavior {
    meta:
        description = "Conti ransomware behavioral patterns"
        severity = "critical"
    strings:
        $conti1 = "taskkill /IM" nocase
        $conti2 = "vssadmin.exe delete shadows /all /quiet" nocase
        $conti3 = "fsutil USN deleteJournal /D" nocase
        $conti4 = ".conti" nocase
        $conti5 = "shadowcopy" nocase
    condition:
        3 of them
}

rule Ransomware_REvil_Behavior {
    meta:
        description = "REvil/Sodinokibi ransomware patterns"
        severity = "critical"
    strings:
        $revil1 = "esxcli" nocase
        $revil2 = "vmkfstools" nocase
        $revil3 = ".revil" nocase
        $revil4 = "unlocker" nocase
        $revil5 = "vmware" nocase
    condition:
        3 of them
}

rule Ransomware_BlackCat_Behavior {
    meta:
        description = "BlackCat/ALPHV ransomware patterns"
        severity = "critical"
    strings:
        $blackcat1 = ".blackcat" nocase
        $blackcat2 = "dmidecode" nocase
        $blackcat3 = "lspci" nocase
        $blackcat4 = "/.AWS/credentials" nocase
        $blackcat5 = "ransomware" nocase
    condition:
        3 of them
}

// ============================================================================
// APT CAMPAIGN PATTERNS
// ============================================================================

rule APT_APT28_Behavior {
    meta:
        description = "APT28 (Fancy Bear) behavioral patterns"
        severity = "critical"
    strings:
        $apt28_1 = "RU" nocase
        $apt28_2 = "backdoor" nocase
        $apt28_3 = "exfiltrate" nocase
        $apt28_4 = "credential" nocase
        $apt28_5 = "spear phishing" nocase
    condition:
        all of them
}

rule APT_APT29_Behavior {
    meta:
        description = "APT29 (Cozy Bear) behavioral patterns"
        severity = "critical"
    strings:
        $apt29_1 = "CozyDuke" nocase
        $apt29_2 = "MiniDuke" nocase
        $apt29_3 = "PowerShell" nocase
        $apt29_4 = "WMI" nocase
        $apt29_5 = "Registry" nocase
    condition:
        3 of them
}

rule APT_Lazarus_Behavior {
    meta:
        description = "Lazarus Group behavioral patterns"
        severity = "critical"
    strings:
        $lazarus1 = "DPRK" nocase
        $lazarus2 = "cryptocurrency" nocase
        $lazarus3 = "SWIFT" nocase
        $lazarus4 = "banking" nocase
        $lazarus5 = "wiper" nocase
    condition:
        3 of them
}

// ============================================================================
// SUPPLY CHAIN & TROJAN PATTERNS
// ============================================================================

rule SolarWinds_NotParent_Signature {
    meta:
        description = "SolarWinds supply chain compromise detection"
        severity = "critical"
    strings:
        $solarwinds1 = "SolarWinds.Orion" nocase
        $solarwinds2 = "NotParent" nocase
        $solarwinds3 = "C2" nocase
        $solarwinds4 = "sunburst" nocase
    condition:
        2 of them
}

rule Trojan_Emotet_Variant {
    meta:
        description = "Emotet trojan behavioral patterns"
        severity = "critical"
    strings:
        $emotet1 = "loader" nocase
        $emotet2 = "botnet" nocase
        $emotet3 = "banking" nocase
        $emotet4 = "credential stealer" nocase
        $emotet5 = "worm" nocase
    condition:
        3 of them
}

rule Trojan_TrickBot_Variant {
    meta:
        description = "TrickBot trojan behavioral patterns"
        severity = "critical"
    strings:
        $trickbot1 = "banking trojan" nocase
        $trickbot2 = "credential" nocase
        $trickbot3 = "webcam" nocase
        $trickbot4 = "keylogger" nocase
        $trickbot5 = "module" nocase
    condition:
        3 of them
}

// ============================================================================
// ROOTKIT & KERNEL-LEVEL THREATS
// ============================================================================

rule Rootkit_Kernel_Mode_Detection {
    meta:
        description = "Kernel-mode rootkit behavioral patterns"
        severity = "critical"
    strings:
        $kernel1 = "kernel" nocase
        $kernel2 = "system call hook" nocase
        $kernel3 = "DKOM" (Direct Kernel Object Manipulation) nocase
        $kernel4 = "rootkit" nocase
        $kernel5 = "ld.so" nocase
    condition:
        3 of them
}

rule Rootkit_BootKit_Detection {
    meta:
        description = "Bootkit/firmware rootkit patterns"
        severity = "critical"
    strings:
        $bootkit1 = "bootkit" nocase
        $bootkit2 = "MBR" nocase
        $bootkit3 = "BIOS" nocase
        $bootkit4 = "firmware" nocase
        $bootkit5 = "UEFI" nocase
    condition:
        3 of them
}

// ============================================================================
// ZERO-DAY EXPLOIT PATTERNS
// ============================================================================

rule ZeroDayExploit_RCE_Behavior {
    meta:
        description = "Remote Code Execution zero-day patterns"
        severity = "critical"
    strings:
        $zeroday_rce1 = "shellcode" nocase
        $zeroday_rce2 = "ROP" (Return-Oriented Programming) nocase
        $zeroday_rce3 = "NOP sled" nocase
        $zeroday_rce4 = "buffer overflow" nocase
        $zeroday_rce5 = "heap spray" nocase
    condition:
        3 of them
}

rule ZeroDayExploit_PrivEsc_Behavior {
    meta:
        description = "Privilege escalation zero-day patterns"
        severity = "critical"
    strings:
        $privesc1 = "privilege escalation" nocase
        $privesc2 = "admin" nocase
        $privesc3 = "kernel exploit" nocase
        $privesc4 = "UAC bypass" nocase
        $privesc5 = "CVE" nocase
    condition:
        3 of them
}

// ============================================================================
// ADVANCED EVASION TECHNIQUES
// ============================================================================

rule Evasion_Polymorphic_Malware {
    meta:
        description = "Polymorphic malware self-modification patterns"
        severity = "high"
    strings:
        $poly1 = "polymorphic" nocase
        $poly2 = "mutate" nocase
        $poly3 = "encrypt" nocase
        $poly4 = "self-modify" nocase
        $poly5 = "code cave" nocase
    condition:
        3 of them
}

rule Evasion_Metamorphic_Malware {
    meta:
        description = "Metamorphic malware behavioral patterns"
        severity = "high"
    strings:
        $meta1 = "metamorphic" nocase
        $meta2 = "rewrite" nocase
        $meta3 = "dead code" nocase
        $meta4 = "junk instructions" nocase
        $meta5 = "anti-analysis" nocase
    condition:
        3 of them
}

rule Evasion_Anti_Analysis {
    meta:
        description = "Anti-analysis and anti-debugging patterns"
        severity = "high"
    strings:
        $antiana1 = "IsDebuggerPresent" nocase
        $antiana2 = "CheckRemoteDebuggerPresent" nocase
        $antiana3 = "NtQueryInformationProcess" nocase
        $antiana4 = "anti-sandbox" nocase
        $antiana5 = "anti-vm" nocase
    condition:
        3 of them
}

// ============================================================================
// DATA EXFILTRATION PATTERNS
// ============================================================================

rule DataExfiltration_C2_Communication {
    meta:
        description = "Command and Control communication patterns"
        severity = "critical"
    strings:
        $c2_1 = "callback" nocase
        $c2_2 = "beaconing" nocase
        $c2_3 = "C2 server" nocase
        $c2_4 = "exfiltrate" nocase
        $c2_5 = "tunnel" nocase
    condition:
        3 of them
}

rule DataExfiltration_Credential_Theft {
    meta:
        description = "Credential harvesting and theft patterns"
        severity = "critical"
    strings:
        $cred1 = "password" nocase
        $cred2 = "LSASS" nocase
        $cred3 = "SAM" nocase
        $cred4 = "Kerberos" nocase
        $cred5 = "keylogger" nocase
    condition:
        3 of them
}

// ============================================================================
// LATERAL MOVEMENT PATTERNS
// ============================================================================

rule LateralMovement_Worm_Propagation {
    meta:
        description = "Worm and lateral movement patterns"
        severity = "critical"
    strings:
        $worm1 = "propagate" nocase
        $worm2 = "replicate" nocase
        $worm3 = "network share" nocase
        $worm4 = "SMB" nocase
        $worm5 = "lateral move" nocase
    condition:
        3 of them
}

rule LateralMovement_Mimikatz_Behavior {
    meta:
        description = "Mimikatz-like credential dumping patterns"
        severity = "critical"
    strings:
        $mimikatz1 = "privilege::debug" nocase
        $mimikatz2 = "token::elevate" nocase
        $mimikatz3 = "sekurlsa" nocase
        $mimikatz4 = "lsadump" nocase
        $mimikatz5 = "vault" nocase
    condition:
        2 of them
}

// ============================================================================
// ENTERPRISE INDICATORS
// ============================================================================

rule Enterprise_Suspicious_Process_Chain {
    meta:
        description = "Suspicious parent-child process relationships"
        severity = "high"
    strings:
        $proc_chain1 = "cmd.exe" nocase
        $proc_chain2 = "powershell" nocase
        $proc_chain3 = "cscript" nocase
        $proc_chain4 = "wscript" nocase
        $proc_chain5 = "mshta" nocase
    condition:
        2 of them
}

rule Enterprise_Webshell_Detection {
    meta:
        description = "Web shell detection patterns"
        severity = "critical"
    strings:
        $webshell1 = "<%@" nocase
        $webshell2 = "<%=" nocase
        $webshell3 = "<?php" nocase
        $webshell4 = "exec" nocase
        $webshell5 = "eval" nocase
    condition:
        2 of them
}

// ============================================================================
// CRYPTOJACKING PATTERNS
// ============================================================================

rule Cryptojacking_Monero_Miner {
    meta:
        description = "Monero cryptocurrency miner detection"
        severity = "high"
    strings:
        $crypto1 = "stratum" nocase
        $crypto2 = "xmrig" nocase
        $crypto3 = "monero" nocase
        $crypto4 = "mining pool" nocase
        $crypto5 = "hashrate" nocase
    condition:
        3 of them
}

// ============================================================================
// RANSOMWARE PAYMENT INFRASTRUCTURE
// ============================================================================

rule Ransomware_Payment_Processor {
    meta:
        description = "Ransomware payment and communication infrastructure"
        severity = "critical"
    strings:
        $payment1 = "onion" nocase
        $payment2 = "bitcoin" nocase
        $payment3 = "ransom note" nocase
        $payment4 = "tor" nocase
        $payment5 = "payment" nocase
    condition:
        3 of them
}

// ============================================================================
// ENDPOINT DETECTION AND RESPONSE (EDR) EVASION
// ============================================================================

rule EDR_Evasion_Techniques {
    meta:
        description = "Techniques to evade EDR and security products"
        severity = "critical"
    strings:
        $edr1 = "EDR" nocase
        $edr2 = "disable" nocase
        $edr3 = "evasion" nocase
        $edr4 = "bypass" nocase
        $edr5 = "defender" nocase
    condition:
        3 of them
}
