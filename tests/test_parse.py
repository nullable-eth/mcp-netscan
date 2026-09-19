from netscan import tools

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="1.2.3.4" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx"/>
        <script id="ssl-cert" output="Subject: CN=example.com"/>
      </port>
    </ports>
    <hostscript><script id="smb-vuln-ms17-010" output="VULNERABLE"/></hostscript>
  </host>
</nmaprun>"""

NUCLEI_JSONL = (
    '{"template-id":"tls-version","info":{"name":"TLS","severity":"info"},'
    '"matched-at":"h:443","type":"ssl"}\n'
    'noise line that is not json\n'
    '{"template-id":"CVE-2021-1","info":{"name":"RCE","severity":"critical"},'
    '"matched-at":"https://h/x","type":"http"}\n'
)

SSLSCAN_XML = """<?xml version="1.0"?>
<document>
  <ssltest host="example.com" port="443">
    <protocol type="tls" version="1.2" enabled="1"/>
    <protocol type="tls" version="1.0" enabled="0"/>
    <cipher status="preferred" sslversion="TLSv1.2" bits="256"
            cipher="ECDHE-RSA-AES256-GCM-SHA384" strength="strong"/>
    <heartbleed sslversion="TLSv1.2" vulnerable="0"/>
    <certificate>
      <subject>CN=example.com</subject>
      <issuer>CN=Let's Encrypt</issuer>
      <not-valid-before>2026-01-01 00:00:00</not-valid-before>
      <not-valid-after>2026-04-01 00:00:00</not-valid-after>
      <signature-algorithm>sha256WithRSAEncryption</signature-algorithm>
    </certificate>
  </ssltest>
</document>"""


def test_parse_nmap():
    r = tools._parse_nmap(NMAP_XML)
    assert len(r["hosts"]) == 1
    h = r["hosts"][0]
    assert h["address"] == "1.2.3.4" and h["state"] == "up"
    p22 = next(p for p in h["ports"] if p["port"] == 22)
    assert p22["service"] == "ssh" and p22["product"] == "OpenSSH"
    p443 = next(p for p in h["ports"] if p["port"] == 443)
    assert p443["scripts"][0]["id"] == "ssl-cert"
    assert h["host_scripts"][0]["id"] == "smb-vuln-ms17-010"


def test_parse_nmap_garbage():
    assert tools._parse_nmap("not xml at all") == {"hosts": []}


def test_parse_nuclei_sorted_and_filtered():
    f = tools._parse_nuclei(NUCLEI_JSONL)
    assert len(f) == 2
    assert f[0]["severity"] == "critical"      # sorted most severe first
    assert f[1]["template"] == "tls-version"


def test_parse_sslscan():
    r = tools._parse_sslscan(SSLSCAN_XML)
    assert r["protocols"] == ["tls 1.2"]
    assert len(r["ciphers"]) == 1
    assert r["certificate"]["subject"] == "CN=example.com"
    assert r["vulnerabilities"] == {}          # heartbleed not vulnerable
