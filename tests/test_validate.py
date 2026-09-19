import pytest

from netscan import validate as v


@pytest.mark.parametrize("t", [
    "192.168.1.1", "10.0.0.0", "example.com", "a.b.c.d.example.io",
    "2001:db8::1", "192.168.1.0/24", "host-name.local", "1.1.1.1",
])
def test_accepts_valid(t):
    assert v.normalize_target(t)


@pytest.mark.parametrize("t", [
    "-oX", "--script=exploit", "1.2.3.4; whoami", "$(id)", "a b",
    "host|cat", "`x`", "a>b", "", "x" * 300, "not_a_host!",
    "192.168.1.1 --script vuln",
])
def test_rejects_bad(t):
    with pytest.raises(v.TargetError):
        v.normalize_target(t)


def test_cidr_size_cap():
    with pytest.raises(v.TargetError):
        v.normalize_target("10.0.0.0/8")            # far too large
    with pytest.raises(v.TargetError):
        v.normalize_target("10.0.0.0/16")           # 65k > default 256
    assert v.normalize_target("10.0.0.0/24")        # /24 is fine
    assert v.normalize_target("10.0.0.0/20", allow_large=True)  # <=4096
    with pytest.raises(v.TargetError):
        v.normalize_target("10.0.0.0/8", allow_large=True)      # still over hard cap


def test_cidr_disallowed_when_flagged():
    with pytest.raises(v.TargetError):
        v.normalize_target("10.0.0.0/24", allow_cidr=False)


@pytest.mark.parametrize("p,ok", [
    ("", True), ("22", True), ("80,443", True), ("1-1024", True),
    ("22,80,443,8080", True), ("70000", False), ("22;rm", False),
    ("-p22", False), ("http", False),
])
def test_ports(p, ok):
    if ok:
        assert v.normalize_ports(p) == p.strip()
    else:
        with pytest.raises(v.TargetError):
            v.normalize_ports(p)


def test_url_defaults_https_and_validates_host():
    url, host = v.normalize_url("example.com/path?q=1")
    assert url == "https://example.com/path?q=1"
    assert host == "example.com"


def test_url_rejects_credentials_and_bad_scheme():
    with pytest.raises(v.TargetError):
        v.normalize_url("http://user:pass@example.com")
    with pytest.raises(v.TargetError):
        v.normalize_url("ftp://example.com")
    with pytest.raises(v.TargetError):
        v.normalize_url("https://-evil")
