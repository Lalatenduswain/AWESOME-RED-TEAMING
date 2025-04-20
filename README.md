# Awesome Red Teaming Resources

A curated list of resources for learning and mastering Red Teaming, designed for beginners and experienced practitioners. This repository focuses on Adversarial Tactics and Techniques aligned with the [MITRE ATT&CK framework](https://attack.mitre.org/). Contributions via Pull Requests are welcome to keep this resource up-to-date.

## Table of Contents
- [Initial Access](#initial-access)
- [Execution](#execution)
- [Persistence](#persistence)
- [Privilege Escalation](#privilege-escalation)
- [Defense Evasion](#defense-evasion)
- [Credential Access](#credential-access)
- [Discovery](#discovery)
- [Lateral Movement](#lateral-movement)
- [Collection](#collection)
- [Exfiltration](#exfiltration)
- [Command and Control](#command-and-control)
- [Embedded and Peripheral Devices Hacking](#embedded-and-peripheral-devices-hacking)
- [Miscellaneous](#miscellaneous)
- [Red Team Gadgets](#red-team-gadgets)
- [Ebooks](#ebooks)
- [Training (Free)](#training-free)
- [Certifications](#certifications)

## Initial Access
- [The Hitchhiker’s Guide to Initial Access](https://posts.specterops.io/the-hitchhikers-guide-to-initial-access-57b66aa80dd6) - Comprehensive guide on gaining initial footholds.
- [Phishing with Empire](https://enigma0x3.net/2016/03/15/phishing-with-empire/) - Techniques for phishing with Empire framework.
- [Cobalt Strike Spear Phishing](https://www.cobaltstrike.com/help-spear-phish) - Documentation on spear phishing with Cobalt Strike.
- [USB Drop Attacks](https://www.redteamsecure.com/usb-drop-attacks-the-danger-of-lost-and-found-thumb-drives/) - Exploiting lost USB drives for initial access.
- [Macro-less Code Execution in MS Word](https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/) - Bypassing macro restrictions.
- [Social Engineering Portal](https://www.social-engineer.org/) - Resources for social engineering techniques.
- [Abusing Microsoft Word Features for Phishing](https://rhinosecuritylabs.com/research/abusing-microsoft-word-features-phishing-subdoc/) - Using Word subDoc for phishing.

## Execution
- [CMSTP.exe Research](https://msitpros.com/?p=3960) - Leveraging CMSTP for code execution.
- [Windows Oneliners for Remote Payload Execution](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/) - Quick commands for payload delivery.
- [WSH Injection Case Study](https://posts.specterops.io/wsh-injection-a-case-study-fd35f79d29dd) - Windows Script Host exploitation.
- [Bypassing AppLocker with PowerShell Diagnostics](https://bohops.com/2017/12/02/clickonce-twice-or-thrice-a-technique-for-social-engineering-and-untrusted-command-execution/) - Evading AppLocker restrictions.

## Persistence
- [A View of Persistence](https://rastamouse.me/blog/view-of-persistence/) - Overview of persistence techniques.
- [Hiding Registry Keys with PSReflect](https://posts.specterops.io/hiding-registry-keys-with-psreflect-b18ec5ac8353) - Stealthy registry manipulation.
- [WMI Persistence with Cobalt Strike](https://blog.inspired-sec.com/archive/2017/01/20/WMI-Persistence.html) - Using WMI for persistence.
- [RunOnceEx Persistence](https://oddvar.moe/2018/03/21/persistence-using-runonceex-hidden-from-autoruns-exe/) - Hidden persistence via RunOnceEx.

## Privilege Escalation
### User Account Control (UAC) Bypass
- [Fileless UAC Bypass with sdclt.exe](https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/) - Bypassing UAC without files.
- [Eventvwr.exe UAC Bypass](https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/) - Registry hijacking for UAC bypass.
- [Exploiting Environment Variables in Scheduled Tasks](https://tyranidslair.blogspot.com/2017/05/exploiting-environment-variables-in.html) - UAC bypass via scheduled tasks.

### Escalation
- [Windows Privilege Escalation Checklist](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md) - Comprehensive escalation checklist.
- [Cobalt Strike Privilege Escalation](https://blog.cobaltstrike.com/2016/12/08/cobalt-strike-3-6-a-path-for-privilege-escalation/) - Techniques using Cobalt Strike.
- [COM Moniker Privilege Escalation](https://blog.inspired-sec.com/archive/2017/03/17/COM-Moniker-Privesc.html) - Exploiting COM objects.

## Defense Evasion
- [Bypassing Device Guard](https://github.com/tyranid/DeviceGuardBypasses) - Techniques to evade Device Guard.
- [Ultimate AppLocker Bypass List](https://github.com/api0cradle/UltimateAppLockerByPassList) - Collection of AppLocker bypass methods.
- [Empire Without PowerShell](https://bneg.io/2017/07/26/empire-without-powershell-exe/) - Evading PowerShell detection.
- [Process Doppelganging](https://hshrzd.wordpress.com/2017/12/18/process-doppelganging-a-new-way-to-impersonate-a-process/) - Advanced process evasion technique.
- [Bypassing AMSI via COM Server Hijacking](https://posts.specterops.io/bypassing-amsi-via-com-server-hijacking-b8a3354d1aff) - Evading Anti-Malware Scan Interface.

## Credential Access
- [Windows Access Tokens and Alternate Credentials](https://blog.cobaltstrike.com/2015/12/16/windows-access-tokens-and-alternate-credentials/) - Token manipulation techniques.
- [Mimikatz DCSync for Domain Hashes](https://adsecurity.org/?p=2053) - Dumping admin credentials.
- [Practical Guide to NTLM Relaying](https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html) - NTLM relay attacks.
- [SCF File for Hash Gathering](https://1337red.wordpress.com/using-a-scf-file-to-gather-hashes/) - Using SCF files for credential harvesting.

## Discovery
- [BloodHound Introduction](https://wald0.com/?p=68) - Mapping Active Directory attack paths.
- [PowerView for Group Scoping](https://www.harmj0y.net/blog/activedirectory/a-pentesters-guide-to-group-scoping/) - Enumerating AD groups.
- [SPN Discovery](https://pentestlab.blog/2018/06/04/spn-discovery/) - Service Principal Name enumeration.
- [Scanning for AD Privileges](https://adsecurity.org/?p=3658) - Identifying privileged accounts.

## Lateral Movement
- [Kerberoasting Without Mimikatz](https://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/) - Extracting service account credentials.
- [Abusing GPO Permissions](https://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/) - Exploiting Group Policy Objects.
- [LethalHTA for DCOM Lateral Movement](https://codewhitesec.blogspot.com/2018/07/lethalhta.html) - Using HTA and DCOM.
- [Pass-the-Hash with LocalAccountTokenFilterPolicy](https://www.harmj0y.net/blog/redteaming/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy/) - Modern PTH techniques.

## Collection
- [Accessing Clipboard from Windows 10 Lock Screen](https://oddvar.moe/2017/01/24/accessing-clipboard-from-the-lock-screen-in-windows-10/) - Part 1 of clipboard exploitation.
- [Clipboard Access Part 2](https://oddvar.moe/2017/01/27/access-clipboard-from-lock-screen-in-windows-10-2/) - Continued exploration of clipboard access.

## Exfiltration
- [DNS Data Exfiltration](https://blog.fosec.vn/dns-data-exfiltration-what-is-this-and-how-to-use-2f6c69998822) - Using DNS for data exfiltration.
- [DET: Data Exfiltration Toolkit](https://github.com/PaulSec/DET) - Extensible exfiltration framework.
- [Formula Injection for Exfiltration](https://www.notsosecure.com/data-exfiltration-formula-injection/) - Exploiting formula injection.

## Command and Control
### Domain Fronting
- [Empire Domain Fronting](https://www.xorrior.com/Empire-Domain-Fronting/) - Using domain fronting with Empire.
- [Finding Frontable Domains](https://github.com/rvrsh3ll/FindFrontableDomains) - Identifying domains for fronting.
- [CloudFront Hijacking](https://www.mindpointgroup.com/blog/pen-test/cloudfront-hijacking/) - Exploiting AWS CloudFront.

### Connection Proxy
- [Cobalt Strike HTTP C2 Redirectors](https://bluescreenofjeff.com/2016-06-28-cobalt-strike-http-c2-redirectors-with-apache-mod_rewrite/) - Setting up redirectors.
- [High-Reputation Redirectors](https://blog.cobaltstrike.com/2017/02/06/high-reputation-redirectors-and-domain-fronting/) - Using trusted domains.

### Web Services
- [C2 with Dropbox](https://pentestlab.blog/2017/08/29/command-and-control-dropbox/) - Using Dropbox for C2.
- [C2 with Twitter](https://pentestlab.blog/2017/09/26/command-and-control-twitter/) - Twitter-based C2.
- [Merlin: HTTP/2 C2 Tool](https://medium.com/@Ne0nd0g/introducing-merlin-645da3c635a) - Cross-platform C2 framework.

### Infrastructure
- [Terraform for Red Team Infrastructure](https://rastamouse.me/blog/terraform-pt1/) - Automating infrastructure deployment.
- [Cobalt Strike Infrastructure Guide](https://blog.cobaltstrike.com/2014/09/09/infrastructure-for-ongoing-red-team-operations/) - Best practices for C2 infrastructure.
- [Malleable C2 Profiles](https://www.cobaltstrike.com/help-malleable-c2) - Customizing C2 communications.

## Embedded and Peripheral Devices Hacking
- [Proxmark3 for RFID Hacking](https://blog.kchung.co/rfid-hacking-with-the-proxmark-3/) - RFID badge cloning.
- [MagSpoof for Magstripe Spoofing](https://github.com/samyk/magspoof) - Credit card spoofing.
- [Keysweeper for Wireless Keyboard Sniffing](https://samy.pl/keysweeper/) - Capturing keystrokes remotely.

## Miscellaneous
- [Red Team Planning Guide](https://github.com/magoo/redteam-plan) - Structuring red team exercises.
- [Adversary Resilience Methodology](https://posts.specterops.io/introducing-the-adversary-resilience-methodology-part-one-e38e06ffd604) - Part 1 of resilience strategies.
- [Awesome Cobalt Strike](https://github.com/zer0yu/Awesome-CobaltStrike) - Cobalt Strike resource collection.

## Red Team Gadgets
### Network Implants
- [LAN Turtle](https://hakshop.com/collections/network-implants/products/lan-turtle) - Network implant for covert access.
- [Packet Squirrel](https://hakshop.com/products/packet-squirrel) - Packet capture and manipulation.
- [Bash Bunny](https://hakshop.com/collections/physical-access/products/bash-bunny) - Multi-payload USB attack platform.

### WiFi Auditing
- [WiFi Pineapple](https://hakshop.com/products/wifi-pineapple) - Wireless auditing platform.
- [Signal Owl](https://shop.hak5.org/products/signal-owl) - WiFi signal intelligence.

### IoT
- [Proxmark3](https://hackerwarehouse.com/product/proxmark3-kit/) - RFID and NFC hacking.
- [Zigbee Sniffer](https://www.attify-store.com/products/zigbee-sniffing-tool-atmel-rzraven) - IoT protocol analysis.

### Software Defined Radio (SDR)
- [HackRF One](https://hackerwarehouse.com/product/hackrf-one-kit/) - Versatile SDR platform.
- [Ubertooth](https://hackerwarehouse.com/product/ubertooth-one/) - Bluetooth monitoring.

### Miscellaneous
- [USB Rubber Ducky](https://hakshop.com/collections/physical-access/products/usb-rubber-ducky-deluxe) - Keystroke injection tool.
- [O.MG Cable](https://shop.hak5.org/collections/featured-makers/products/o-mg-cable) - Malicious USB cable.

## Ebooks
- [The Hacker Playbook 3](https://www.amazon.com/Hacker-Playbook-Practical-Penetration-Testing-ebook/dp/B07CSPFYZ2) - Practical penetration testing guide.
- [Advanced Penetration Testing](https://www.amazon.com/Advanced-Penetration-Testing-Hacking-Networks/dp/1119367689) - Hacking secure networks.
- [Social Engineers' Playbook](https://www.amazon.com/Social-Engineers-Playbook-Practical-Pretexting/dp/0692306617/) - Pretexting techniques.

## Training (Free)
- [Tradecraft: Red Team Operations](https://www.youtube.com/watch?v=IRpS7oZ3z0o&list=PL9HO6M_MU2nesxSmhJjEvwLhUoHPHmXvz) - Free course on red team tactics.
- [Advanced Threat Tactics](https://blog.cobaltstrike.com/2015/09/30/advanced-threat-tactics-course-and-notes/) - Cobalt Strike training.
- [DetectionLab Setup](https://www.c2.lol/articles/setting-up-chris-longs-detectionlab) - Building a home AD lab.

## Certifications
- [CREST Certified Simulated Attack Specialist](http://www.crest-approved.org/examination/certified-simulated-attack-specialist/) - Advanced red team certification.
- [SANS SEC564: Red Team Operations](https://www.sans.org/course/red-team-operations-and-threat-emulation) - Threat emulation training.
- [Certified Red Team Professional](https://www.pentesteracademy.com/activedirectorylab) - Active Directory-focused certification.