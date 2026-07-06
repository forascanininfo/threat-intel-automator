
# Threat Intelligence Automator

Threat Intelligence Automator is an automated system for the detection, analysis, and active response to network threats. The tool leverages global Threat Intelligence sources to evaluate IP address reputation in real time, generate professional PDF incident reports, and automatically block malicious actors at the operating system level.

Parallel analysis of IP addresses across three leading security services:
- AbuseIPDB: Verification of reporting history, Abuse Score, and attack category.
- VirusTotal: Reputation analysis through more than 90 antivirus and network scanners.
- AlienVault OTX: Identification of associated threats (Pulses) and indicators of compromise 
It is possible to perform the analysis of a single specific IP address or conduct a group analysis via a textual list (.txt).

An IP address is classified as high‑risk and automatically blocked if it meets at least one of the following two conditions:
- AbuseIPDB indicator: The Abuse Score exceeds 80%.
- VirusTotal indicator: The number of positive malicious detections reported by independent security scanners exceeds 3.

The automated blocking mechanism is cross-platform, dynamically supporting Windows Firewall (via netsh) and Linux (via iptables) depending on the host environment.

# API Key Configuration
For full analysis functionality, you need to register on the official platforms and obtain free API keys:
- AbuseIPDB (Create account → API → Create Key)
- VirusTotal (Create account → Profile → API Key)
- AlienVault OTX (Create account → API Homepage)

In the root folder of the project, create a file named .env and paste your keys in the following format:

ABUSEIPDB_API_KEY=your_abuseipdb_key_here
VIRUSTOTAL_API_KEY=your_virustotal_key_here
ALIENVAULT_API_KEY=your_alienvault_key_here

