
rule DefaultMalwareIndicators {
    meta:
        description = "Default malware indicators"
        author = "SentinelX"
    strings:
        $suspicious_api1 = "CreateRemoteThread"
        $suspicious_api2 = "WriteProcessMemory"
        $suspicious_api3 = "VirtualAllocEx"
    condition:
        any of them
}
