rule TTP_MSC_EvilTwin_Attack {
    meta:
        description = "Detects malicious MSC files used in Evil Twin attacks (abusing legitimate MMC snap-ins)"
        author = "Amr Fathy - @1nclud3"
        date = "2025-03-30"
        reference = "https://attack.mitre.org/techniques/T1036/004/"
        reference = "https://www.trendmicro.com/en_us/research/25/c/cve-2025-26633-water-gamayun.html"
    strings:
        // MSC File Structure Indicators
        $msc_xml_header = "<?xml version=\"1.0\"?><MMC_ConsoleFile" nocase wide ascii
        $msc_snapin_tag = "<SnapIn" nocase wide ascii
        $msc_binary_tag = "<Binary" nocase wide ascii

        // Malicious Patterns
        $mal_b64encoded_shockwave_flash_ocx = "ocx_streamorstorage" base64wide // Found in base64 encoded data in <Binary> tag
        $mal_http = "http" nocase wide ascii // Indication of URL
        $mal_shockwave_flash = "Shockwave" nocase wide ascii // Indication of using Shockwave Flash Object
        
    condition:
        // MSC File Structure 
        (2 of ($msc_*))
        and
        // Malicious indicators
        (any of ($mal_*))
    
}