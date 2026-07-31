# r1-reachability
Python script for checking required ports to RUCKUS One Network Controller Port Checks. 

Rewritten with copilot to provide a nicer output, cert checking, pass / fail per region and output to json files. 

Note the hosts file is correct as of the Aug 2026. The host list can be checked within R1. A machine readable list might simplify updates in the future. 

The host file has been broken into section for regions. A pass or fail is given for each region in the 1st table and then for each individual host in the second table. 

port_checker_r1.py
Version: 1.1.0

Ruckus One readiness checker using Python built-in libraries only.

What it checks
--------------
- DNS resolution for all entries
- TCP connect for TCP services
- UDP basic probe for UDP services
- TLS handshake and certificate validity for TCP/443 services
- Region readiness for Ruckus One zones: GLOBAL, US, EU, APAC

Host file format
----------------
Use markdown-style headings to group services:

    # GLOBAL
    ap-registrar.ruckuswireless.com,443
    sw-registrar.ruckuswireless.com,443
    storage.googleapis.com,443

    # US
    ruckus.cloud,443
    device.ruckus.cloud,443
    edge-docker-registry.ruckus.cloud,443
    outgoing.ruckus.cloud,1812
    outgoing.ruckus.cloud,1813

    # EU
    eu.ruckus.cloud,443
    device.eu.ruckus.cloud,443

    # APAC
    asia.ruckus.cloud,443
    device.asia.ruckus.cloud,443

Input formats supported
-----------------------
    host,port
    host,port,protocol
    host,port,protocol,description
    https://ruckus.cloud
    device.ruckus.cloud:443

Notes
-----
- Markdown headings are recognised: # GLOBAL, ## US, ### EU, # APAC, # ASIA
- Blank lines are ignored.
- Comment lines starting with # are ignored unless they are recognised zone headings.
- If protocol is omitted, TCP is assumed except ports 1812 and 1813, which default to UDP.
- For zone readiness, TCP/443 requires DNS OK, TCP OPEN, TLS OK and cert_valid True.
- TCP/80 and TCP/22 require DNS OK and TCP OPEN.
- UDP services default to DNS-only pass logic to avoid false failure from generic UDP probes.
  Use --udp-strict if you want UDP_NO_RESPONSE to fail readiness.

Example usage
-------------
    python3 port_checker_r1.py -i hosts_r1.csv
    python3 port_checker_r1.py -i hosts_r1.csv -o results.csv -j results.json
    python3 port_checker_r1.py -i hosts_r1.csv --workers 30 --timeout 5
    python3 port_checker_r1.py -i hosts_r1.csv --udp-strict
"""

<img width="2403" height="1105" alt="image" src="https://github.com/user-attachments/assets/1c8afe7f-f58e-4f6b-81a6-20c9f6cfb15f" />
