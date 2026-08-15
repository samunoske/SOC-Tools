<!--
  ⚠️ AUTO-GENERATED FILE. Do not edit directly.
  Edit data/tools.json and run: npm run build
-->

<div align="center">

# 🛡️ SOC Tools

**Collection of free & open-source web tools for Information Security, built for Security Operations Center (SOC) analysts**

![Tools](https://img.shields.io/badge/Tools-85-2ea44f)
![Categories](https://img.shields.io/badge/Categories-13-2ea44f)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

> 🌐 Browse the interactive, searchable version: **https://samunoske.github.io/SOC-Tools** ·
> ⚠️ Items marked **Free tier** offer a free account tier with usage limits or trial-based access.

</div>


> [!WARNING]
> **Protect sensitive data when using free tools.**
> Free access does not mean free of responsibility. It is your duty, as the user, analyst, or researcher, to do due diligence before submitting any data to these services. Do not submit PII, PHI, confidential, proprietary, personal, or classified (e.g., Top Secret) data to free tools. Some services share submissions and results with the community, and there is no guarantee that anything you upload will be removed or deleted. Review each service's privacy policy and terms of service before uploading sensitive information. Always comply with your organization's or company's acceptable use policy when using these tools, and if you are using them for your own purposes, choose options that align with your personal risk tolerance and threat model.

## 📑 Table of Contents

- [🔓 Encoded Data & Decoders](#encoded-data-decoders)
- [🌐 IP Check Tools](#ip-check-tools)
- [🧭 DNS Check Tools](#dns-check-tools)
- [🔗 URL Check & Risk](#url-check-risk)
- [🦠 Malware & File Analysis](#malware-file-analysis)
- [🎯 Threat Intelligence & IOC](#threat-intelligence-ioc)
- [📧 Phishing & Email Analysis](#phishing-email-analysis)
- [📡 Packet & Network Analysis](#packet-network-analysis)
- [🕵️ OSINT](#osint)
- [🔑 Hash & Password Tools](#hash-password-tools)
- [🔎 Query Conversions](#query-conversions)
- [📶 Service Status Pages](#service-status-pages)
- [🧰 Miscellaneous](#miscellaneous)

---

## 🔓 Encoded Data & Decoders

> Decode, deobfuscate, and transform encoded or obfuscated data.

| Tool | Description | Tags | Access |
| :--- | :--- | :--- | :--- |
| [CyberChef](https://gchq.github.io/CyberChef/) | The Cyber Swiss Army Knife for encoding, decoding, encryption, and data analysis. | `encode` · `decode` · `crypto` | ✅ Free |
| [JavaScript Deobfuscator](https://deobfuscate.io/) | Deobfuscate and beautify obfuscated JavaScript. | `javascript` · `deobfuscation` | ✅ Free |
| [UnPHP](https://www.unphp.net) | Decode and deobfuscate PHP files. | `php` · `deobfuscation` | ✅ Free |
| [Base64 Decoder](https://www.base64decode.org/) | Decode Base64-encoded strings. | `base64` · `decode` | ✅ Free |
| [Base64 to DOC](https://products.aspose.app/pdf/conversion/base64-to-docx) | Convert Base64 content into DOC/DOCX documents. | `base64` · `document` | ✅ Free |
| [URL Decoder](https://www.urldecoder.org/) | Decode percent-encoded URLs and query parameters. | `url` · `decode` | ✅ Free |
| [User Agent Decoder](https://user-agents.net/) | Parse and inspect browser user-agent strings. | `user-agent` · `parse` | ✅ Free |
| [Cipher Identifier](https://www.dcode.fr/cipher-identifier) | Identify unknown ciphers and encodings from sample text. | `cipher` · `crypto` | ✅ Free |

---

## 🌐 IP Check Tools

> Check IP reputation, geolocation, and network ownership.

| Tool | Description | Tags | Access |
| :--- | :--- | :--- | :--- |
| [AbuseIPDB](https://www.abuseipdb.com/) | Check and report abusive IP addresses using community reports. _(Free account: limited lookups/day)_ | `reputation` · `abuse` | ⚠️ Free tier |
| [GreyNoise](https://viz.greynoise.io/) | Filter internet background noise so analysts can focus on real threats. _(Community plan: limited lookups/month)_ | `triage` · `noise` | ⚠️ Free tier |
| [IPInfo](https://ipinfo.io/) | IP geolocation, ASN, hostname, and company lookup. _(Free tier: 50k requests/month)_ | `geolocation` · `asn` | ⚠️ Free tier |
| [Shodan](https://www.shodan.io) | Search engine for internet-connected devices and services. _(Free account: limited results and API credits)_ | `scanning` · `devices` | ⚠️ Free tier |
| [Censys](https://search.censys.io/) | Search hosts, certificates, and services across the internet. _(Free account: limited queries/month)_ | `scanning` · `certificates` | ⚠️ Free tier |
| [BGPView](https://bgpview.io/) | Inspect ASNs, prefixes, and BGP routing data. | `bgp` · `asn` | ✅ Free |
| [Team Cymru IP-to-ASN](https://asn.cymru.com/cgi-bin/whois.cgi) | Whois-style ASN lookup for any IP address. | `asn` · `lookup` | ✅ Free |
| [IPVoid](https://www.ipvoid.com) | IP and domain blacklist checks against multiple blocklists. | `blacklist` · `reputation` | ✅ Free |

---

## 🧭 DNS Check Tools

> Analyze DNS records, domains, subdomains, and registration data.

| Tool | Description | Tags | Access |
| :--- | :--- | :--- | :--- |
| [DNS Dumpster](https://dnsdumpster.com/) | Passive DNS reconnaissance with subdomain and host mapping. | `recon` · `dns` | ✅ Free |
| [ViewDNS](https://www.viewdns.info) | Reverse DNS, whois, subdomain, and IP history lookups. | `whois` · `reverse-dns` | ✅ Free |
| [crt.sh](https://crt.sh/) | Search certificate transparency logs for domains and subdomains. | `certificates` · `subdomains` | ✅ Free |
| [MXToolbox](https://mxtoolbox.com/) | DNS, SMTP, and MX diagnostics with blacklist checks. _(Free account: limited lookups/day)_ | `dns` · `smtp` · `blacklist` | ⚠️ Free tier |
| [SecurityTrails](https://securitytrails.com/) | Historical DNS, whois, and subdomain data (free tier). _(Free account: limited queries/day)_ | `dns-history` · `whois` | ⚠️ Free tier |
| [RDAP.org](https://www.rdap.org/) | Modern registration data lookup (RDAP) for domains and IPs. | `rdap` · `whois` | ✅ Free |

---

## 🔗 URL Check & Risk

> Investigate URL safety, reputation, hosting, and screenshot behavior.

| Tool | Description | Tags | Access |
| :--- | :--- | :--- | :--- |
| [URLScan](https://www.urlscan.io) | Screenshot and behavioral analysis of URLs with rich results. _(Free account: limited scans/month)_ | `screenshot` · `detonation` | ⚠️ Free tier |
| [Browserling](https://www.browserling.com) | Live cross-browser rendering and interaction with URLs. _(Free plan: limited live browser sessions)_ | `screenshot` · `browser` | ⚠️ Free tier |
| [URLHaus](https://urlhaus.abuse.ch/browse/) | Database of malicious URLs and domains used in campaigns. | `malicious` · `feed` | ✅ Free |
| [URLVoid](https://www.urlvoid.com) | Multi-engine URL reputation and blacklist checks. | `reputation` · `blacklist` | ✅ Free |
| [Google Safe Browsing](https://transparencyreport.google.com/safe-browsing/search) | Check if Google classifies a URL as unsafe. | `safe-browsing` · `reputation` | ✅ Free |
| [Netcraft Site Report](https://sitereport.netcraft.com/) | Hosting, technology, and takedown analysis of a website. | `hosting` · `uptime` | ✅ Free |
| [PhishTank](https://www.phishtank.com/) | Community-verified database of phishing URLs. | `phishing` · `feed` | ✅ Free |
| [OpenPhish](https://openphish.com/) | Free phishing intelligence feed of malicious URLs. | `phishing` · `feed` | ✅ Free |
| [Trend Micro URL Check](https://global.sitesafety.trendmicro.com/) | URL safety rating from Trend Micro. | `reputation` · `rating` | ✅ Free |
| [Zscaler Zulu](https://zulu.zscaler.com/) | URL risk identifier from Zscaler. | `reputation` · `rating` | ✅ Free |

---

## 🦠 Malware & File Analysis

> Detonate and analyze suspicious files and malware samples.

| Tool | Description | Tags | Access |
| :--- | :--- | :--- | :--- |
| [VirusTotal](https://www.virustotal.com) | Multi-AV scanning of files and URLs. _(Free account: rate-limited scanning)_ | `scanning` · `av` | ⚠️ Free tier |
| [Malware Bazaar](https://bazaar.abuse.ch/browse/) | Community malware sample repository by abuse.ch. | `samples` · `feed` | ✅ Free |
| [Triage](https://tria.ge/reports/public) | Cloud malware sandbox with public detonation reports. _(Public reports free; private analysis is paid)_ | `sandbox` · `detonation` | ⚠️ Free tier |
| [Hybrid Analysis](https://www.hybrid-analysis.com/) | Crowd-sourced Falcon sandbox detonation reports. _(Free account: limited submissions/day)_ | `sandbox` · `detonation` | ⚠️ Free tier |
| [Any.Run](https://any.run/) | Interactive malware analysis sandbox. _(Free plan: limited interactive sessions/day)_ | `sandbox` · `interactive` | ⚠️ Free tier |
| [Joe Sandbox](https://www.joesandbox.com/) | Deep automated malware analysis platform (free analysis). _(Free community analysis with usage limits)_ | `sandbox` · `automation` | ⚠️ Free tier |
| [Intezer Analyze](https://analyze.intezer.com/) | Genome-based malware analysis with code reuse detection. _(Free tier: limited analyses)_ | `analysis` · `attribution` | ⚠️ Free tier |
| [UnpacMe](https://www.unpac.me/) | Automated malware unpacking service. | `unpacking` · `packer` | ✅ Free |
| [MalShare](https://malshare.com/) | Malware sample collection and search. _(Free account: limited sample downloads)_ | `samples` · `feed` | ⚠️ Free tier |
| [MalAPI.io](https://malapi.io/) | Reference for Windows APIs abused by malware. | `windows` · `reference` | ✅ Free |
| [Awesome Malware Analysis](https://github.com/rshipp/awesome-malware-analysis) | Curated list of malware analysis tools and resources. | `reference` · `curated-list` | ✅ Free |

---

## 🎯 Threat Intelligence & IOC

> Feeds, platforms, and knowledge bases for threat intelligence.

| Tool | Description | Tags | Access |
| :--- | :--- | :--- | :--- |
| [ThreatFox](https://threatfox.abuse.ch/browse/) | IOC sharing platform from abuse.ch. | `ioc` · `feed` | ✅ Free |
| [AlienVault OTX](https://otx.alienvault.com/) | Open Threat Exchange (community threat intel and pulses). | `ti` · `pulses` | ✅ Free |
| [MITRE ATT&CK](https://attack.mitre.org/) | Knowledge base of adversary tactics, techniques, and procedures. | `framework` · `tactics` | ✅ Free |
| [Malpedia](https://malpedia.org/) | YARA rules and profiles for malware families. | `families` · `yara` | ✅ Free |
| [Feodo Tracker](https://feodotracker.abuse.ch/) | Botnet C2 infrastructure tracker. | `botnet` · `c2` | ✅ Free |
| [Valhalla](https://valhalla.nextron-systems.com/) | Searchable YARA rule repository. | `yara` · `rules` | ✅ Free |

---

## 📧 Phishing & Email Analysis

> Parse email headers and investigate phishing campaigns.

| Tool | Description | Tags | Access |
| :--- | :--- | :--- | :--- |
| [PhishTool](https://www.phishtool.com/) | Phishing email analysis, orchestration, and reporting (free tier). _(Free plan: limited email analysis)_ | `email` · `phishing` | ⚠️ Free tier |
| [Google Messageheader](https://toolbox.googleapps.com/apps/messageheader/) | Parse raw email headers to trace delivery paths. | `headers` · `email` | ✅ Free |
| [Microsoft Message Header Analyzer](https://mha.azurewebsites.net/) | Official Microsoft header analyzer that breaks down delivery hops and timestamps. | `headers` · `email` · `microsoft` | ✅ Free |
| [MXToolbox Email Headers](https://mxtoolbox.com/EmailHeaders.aspx) | Decode email headers and check SPF/DKIM/DMARC. _(Free account: limited lookups/day)_ | `headers` · `spf-dkim-dmarc` | ⚠️ Free tier |
| [EmailRep](https://emailrep.io/) | Email address reputation and risk scoring. _(Free tier: rate-limited lookups)_ | `reputation` · `email` | ⚠️ Free tier |
| [PhishStats](https://phishstats.info/) | Searchable phishing statistics and malicious domain data. | `phishing` · `stats` | ✅ Free |
| [mail-tester.com](https://www.mail-tester.com/) | Score email deliverability and spoofing configuration. | `deliverability` · `dns` | ✅ Free |
| [Spamhaus](https://www.spamhaus.org/) | Spam and malware blocklist lookups. | `blocklist` · `spam` | ✅ Free |

---

## 📡 Packet & Network Analysis

> Analyze packet captures and network traffic in the browser.

| Tool | Description | Tags | Access |
| :--- | :--- | :--- | :--- |
| [A-Packets](https://apackets.com/) | Free online PCAP analyzer with protocol dissection. | `pcap` · `analysis` | ✅ Free |

---

## 🕵️ OSINT

> Gather and correlate open-source intelligence on entities.

| Tool | Description | Tags | Access |
| :--- | :--- | :--- | :--- |
| [OSINT Framework](https://osintframework.com/) | Categorized directory of OSINT tools and resources. | `directory` · `reference` | ✅ Free |
| [Have I Been Pwned](https://haveibeenpwned.com/) | Check email addresses against known data breaches. | `breaches` · `creds` | ✅ Free |
| [Wayback Machine](https://web.archive.org/) | Historical snapshots of web pages. | `history` · `archive` | ✅ Free |
| [Hunter.io](https://hunter.io/) | Find email addresses and analyze domains (free tier). _(Free plan: 25 searches & 50 lookups/month)_ | `emails` · `domain` | ⚠️ Free tier |
| [TinEye](https://tineye.com/) | Reverse image search. _(Free plan: limited reverse-image searches)_ | `image` · `search` | ⚠️ Free tier |
| [Epieos](https://epieos.com/) | Free email and phone OSINT lookup service. | `email` · `osint` | ✅ Free |

---

## 🔑 Hash & Password Tools

> Identify, look up, and crack password hashes.

| Tool | Description | Tags | Access |
| :--- | :--- | :--- | :--- |
| [CrackStation](https://crackstation.net/) | Free online password hash lookup. | `lookup` · `online` | ✅ Free |
| [Hashes.org](https://hashes.org/) | Online hash database and cracking statistics. | `lookup` · `online` | ✅ Free |
| [Name That Hash](https://nth.skerritt.blog/) | Identify unknown hash types. | `identify` · `reference` | ✅ Free |

---

## 🔎 Query Conversions

> Convert queries between SIEM formats and craft regex.

| Tool | Description | Tags | Access |
| :--- | :--- | :--- | :--- |
| [Uncoder.io](https://uncoder.io/) | Convert detection queries between SIEM formats. | `siem` · `conversion` | ✅ Free |
| [regex101](https://regex101.com/) | Interactive regex tester and debugger. | `regex` · `testing` | ✅ Free |
| [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) | Visualize and annotate ATT&CK coverage. | `attck` · `mapping` | ✅ Free |

---

## 📶 Service Status Pages

> Monitor service health and outages.

| Tool | Description | Tags | Access |
| :--- | :--- | :--- | :--- |
| [Microsoft 365 Health](https://portal.office.com/servicestatus) | Microsoft 365 service health and incidents. | `microsoft` · `cloud` | ✅ Free |
| [DownDetector](https://downdetector.com/) | Crowd-sourced outage reports for services. | `outages` · `crowd` | ✅ Free |
| [AWS Service Health](https://status.aws.amazon.com/) | AWS regional service status. | `aws` · `cloud` | ✅ Free |
| [Azure Status](https://azure.status.microsoft/) | Azure service health and incidents. | `azure` · `cloud` | ✅ Free |
| [Google Cloud Status](https://status.cloud.google.com/) | Google Cloud service status. | `gcp` · `cloud` | ✅ Free |
| [Apple System Status](https://www.apple.com/support/systemstatus/) | Apple services availability. | `apple` · `status` | ✅ Free |

---

## 🧰 Miscellaneous

> Everything else worth bookmarking.

| Tool | Description | Tags | Access |
| :--- | :--- | :--- | :--- |
| [WTFBins](https://wtfbins.wtf/) | Windows binaries that can be abused (LOLBins). | `lolbins` · `windows` | ✅ Free |
| [GTFOBins](https://gtfobins.github.io/) | Unix binaries that can be abused for privilege escalation. | `privesc` · `linux` | ✅ Free |
| [LOLBAS](https://lolbas-project.github.io/) | Living-off-the-land Windows binaries and scripts. | `lolbins` · `windows` | ✅ Free |
| [AttackerKB](https://attackerkb.com/) | Community assessments of CVEs. | `cve` · `knowledge` | ✅ Free |
| [MAC Address Lookup](https://macaddress.io/) | OUI lookup for MAC vendor identification. | `mac` · `lookup` | ✅ Free |
| [SOC CMM](https://soc-cmm.com) | Assess and benchmark SOC capability and maturity. | `soc` · `maturity` | ✅ Free |
| [ExplainShell](https://explainshell.com/) | Break down and explain shell commands. | `shell` · `reference` | ✅ Free |
| [IP CIDR Guide](https://www.ipaddressguide.com/cidr) | CIDR and subnet reference guide. | `networking` · `reference` | ✅ Free |
| [Remini](https://app.remini.ai/) | AI photo enhancer for clarifying screenshots. | `images` · `ai` | ✅ Free |

---

## ➕ Adding a Tool

1. Add or update an entry in [`data/tools.json`](data/tools.json).
2. Run `npm run build` to regenerate `README.md` and `docs/index.html`.
3. Open a pull request.

## 📜 License

[GPL-3.0](LICENSE)

---

<div align="center">

**85 tools** · **13 categories** · 21 with limited/free-tier access

Generated by [`scripts/build.js`](scripts/build.js) from [`data/tools.json`](data/tools.json)

</div>
