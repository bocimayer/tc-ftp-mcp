"""End to end against a throwaway local FTP server (pyftpdlib)."""

import threading

import pytest

pyftpdlib = pytest.importorskip("pyftpdlib")
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

from tc_ftp_mcp import client, server
from tc_ftp_mcp.crypto import encode_password
from tc_ftp_mcp.sessions import load_sessions


@pytest.fixture
def ftp_env(tmp_path):
    root = tmp_path / "root"
    (root / "sub").mkdir(parents=True)
    (root / "hello.txt").write_bytes("szia világ\n".encode("utf-8"))

    auth = DummyAuthorizer()
    auth.add_user("tester", "p4ss-é", str(root), perm="elradfmw")
    handler = type("H", (FTPHandler,), {"authorizer": auth})
    srv = FTPServer(("127.0.0.1", 0), handler)
    port = srv.address[1]
    t = threading.Thread(target=srv.serve_forever, kwargs={"timeout": 0.1}, daemon=True)
    t.start()

    ini = tmp_path / "wcx_ftp.ini"
    ini.write_text(
        f"[demo]\nhost=127.0.0.1:{port}\nusername=tester\npassword={encode_password('p4ss-é')}\npasvmode=1\n",
        encoding="cp1250",
    )
    server._ini_path = ini
    yield root
    srv.close_all()
    server._ini_path = None


def test_list_and_read(ftp_env):
    names = {e["name"]: e["type"] for e in server.list_dir("demo")}
    assert names == {"sub": "dir", "hello.txt": "file"}
    assert server.read_text("demo", "hello.txt") == "szia világ\n"


def test_download_upload_rename_delete(ftp_env, tmp_path):
    dest = tmp_path / "got.txt"
    assert server.download_file("demo", "hello.txt", str(dest)).startswith("downloaded")
    assert dest.read_bytes().decode("utf-8") == "szia világ\n"
    assert server.download_file("demo", "hello.txt", str(dest)).startswith("refused")

    src = tmp_path / "up.txt"
    src.write_text("x")
    assert server.upload_file("demo", str(src), "up.txt").startswith("uploaded")
    assert server.upload_file("demo", str(src), "up.txt").startswith("refused")
    assert server.upload_file("demo", str(src), "up.txt", overwrite=True).startswith("uploaded")

    assert server.make_dir("demo", "newdir").startswith("created")
    assert server.rename("demo", "up.txt", "newdir/up2.txt").startswith("renamed")
    assert (ftp_env / "newdir" / "up2.txt").exists()
    assert server.delete_file("demo", "newdir/up2.txt").startswith("deleted")
    assert not (ftp_env / "newdir" / "up2.txt").exists()


def test_errors_are_strings_not_exceptions(ftp_env):
    assert server.read_text("demo", "missing.txt").startswith("error_perm")
    assert server.list_dir("no such session").startswith("SessionError")


def test_list_sessions_hides_password(ftp_env):
    out = server.list_sessions()
    assert out and "password" not in out[0] and out[0]["has_password"] is True


def test_read_text_cap(ftp_env):
    (ftp_env / "big.txt").write_bytes(b"a" * 5000)
    out = server.read_text("demo", "big.txt", max_bytes=100)
    assert out == "a" * 100 + "\n[truncated]"
    # connection still usable afterwards
    assert server.read_text("demo", "hello.txt") == "szia világ\n"
