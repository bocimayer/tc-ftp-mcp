import pytest

from tc_ftp_mcp.crypto import PasswordDecodeError, decode_password, encode_password
from tc_ftp_mcp.sessions import SessionError, find_session, load_sessions


@pytest.mark.parametrize("plain", ["a", "hunter2", "Pässwörd-ő-ű 123!", "x" * 60])
def test_round_trip(plain):
    assert decode_password(encode_password(plain)) == plain


@pytest.mark.parametrize("bad", ["", "zz", "abc", "0102030405"[:8]])
def test_bad_input(bad):
    with pytest.raises(PasswordDecodeError):
        decode_password(bad)


INI = """[connections]
1=demo
[default]
pasvmode=1
[folder|demo one]
host=ftp.example.test:2121
username=alice
password={pw}
pasvmode=0
directory=/www
[demo two]
host=ftps://secure.example.test
username=bob
[CertAlias]
x=y
"""


@pytest.fixture
def ini(tmp_path):
    p = tmp_path / "wcx_ftp.ini"
    p.write_text(INI.format(pw=encode_password("s3cret")), encoding="cp1250")
    return p


def test_load(ini):
    s = load_sessions(ini)
    assert set(s) == {"folder|demo one", "demo two"}
    one = s["folder|demo one"]
    assert (one.host, one.port, one.username, one.directory) == ("ftp.example.test", 2121, "alice", "/www")
    assert one.passive is False and one.tls is False
    assert one.folder == "folder" and one.label == "demo one"
    assert one.password() == "s3cret"
    assert "password" not in one.public() and "s3cret" not in repr(one)
    two = s["demo two"]
    assert two.tls is True and two.port == 21 and two.password() == ""


def test_find(ini):
    s = load_sessions(ini)
    assert find_session(s, "demo one").name == "folder|demo one"
    assert find_session(s, "DEMO TWO").name == "demo two"
    with pytest.raises(SessionError):
        find_session(s, "demo")  # ambiguous
    with pytest.raises(SessionError):
        find_session(s, "nope")


def test_cert_pin_and_alias(tmp_path):
    ini = tmp_path / "wcx_ftp.ini"
    ini.write_text(
        "[s]\nhost=ftps://Shared.example.test\nusername=u\n"
        "[CertAlias]\nshared.example.test=real.example.test\n"
        "[CertSHA256hashes]\nshared.example.test=AA:BB\n",
        encoding="cp1250",
    )
    s = load_sessions(ini)["s"]
    assert s.tls and s.cert_alias == "real.example.test" and s.pinned_sha256 == "AA:BB"


def test_trust_store(tmp_path):
    from tc_ftp_mcp import trust

    store = tmp_path / "t.json"
    assert trust.trusted("Host.Test", store) == set()
    trust.add("Host.Test", "aa:bb", store)
    assert trust.trusted("host.test", store) == {"AA:BB"}
