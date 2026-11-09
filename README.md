# vuln_hunter

Continuous random-IP vulnerability discovery tool.

> **WARNING — READ CAREFULLY BEFORE USING**  
> This software is provided strictly for educational, research, and authorized security testing purposes only.  
> Unauthorized scanning, probing, or access of computer systems you do notpossess is illegal under the laws of most countries (including the U.S. Computer Fraud and Abuse Act, the UK Computer Misuse Act, and equivalent laws elsewhere).  
> The author assumes **no liability** for any misuse, damage, legal consequences, or other outcomes resulting from the use of this tool.  
> By downloading, copying, or running this software, you accept full and sole responsibility for your actions.

## Description

`vuln_hunter.py` generates random public IPv4 addresses, probes common ports, collects banners, and runs a set of lightweight vulnerability checks. It continues until it finds a host that fails one of the checks, then stops and records the evidence.

It is intended as a learning and research tool for understanding internet-wide scanning techniques and common misconfigurations.

## Features

- Random public IPv4 generation (excludes private, reserved, multicast, and CGNAT ranges)
- Concurrent scanning with configurable worker count
- Banner grabbing
- Lightweight vulnerability checks for:
  - Anonymous FTP
  - Unauthenticated Redis
  - Unauthenticated MongoDB
  - Open RDP
  - SMB exposure
  - Outdated or interesting HTTP services
- Verbose mode for detailed output
- Stops on first confirmed vulnerable host
- Writes results to `vuln_hit.txt`

## Legal Disclaimer

This project is provided **as is**, without warranty of any kind, express or implied.  

The author(s) and contributors shall not be liable for any claim, damages, legal fees, criminal charges, civil liability, or other liability arising from the use or inability to use this software.

**You are solely responsible for ensuring that your use of this tool complies with all applicable local, state, national, and international laws.**

Unauthorized scanning of systems you do not own or do not have explicit written permission to test is illegal. Running this tool against random internet addresses without authorization may result in criminal prosecution, civil lawsuits, or both.

This tool does **not** contain exploits that take control of remote systems. It only performs passive and lightly active checks for known misconfigurations. Even so, such activity can still be considered unauthorized access under many legal frameworks.

## Requirements

- Python 3.10 or newer
- No third-party dependencies

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/vuln_hunter.git
cd vuln_hunter
chmod +x vuln_hunter.py
python3 vuln_hunter.py [options]

