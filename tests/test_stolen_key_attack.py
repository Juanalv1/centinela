"""stolen_key_attack.py: slow paginated export that stops itself once the key is revoked."""
import http.server
import json
import threading
from urllib.parse import parse_qs, urlsplit

import pytest

from conftest import ROOT, load_module

attack = load_module("stolen_key_attack", ROOT / "lab" / "attack" / "stolen_key_attack.py")


class _Victim(http.server.BaseHTTPRequestHandler):
    revoke_after = 3  # class attribute set per test
    seen: list = []

    def do_GET(self):
        url = urlsplit(self.path)
        _Victim.seen.append({"path": url.path, "page": parse_qs(url.query).get("page", [None])[0],
                             "key": self.headers.get("X-API-Key")})
        ok = len(_Victim.seen) <= _Victim.revoke_after
        body = json.dumps({"customers": [{"id": 1}]} if ok else {"error": "unauthorized"}).encode()
        self.send_response(200 if ok else 401)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture()
def victim():
    _Victim.seen = []
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Victim)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_stops_as_soon_as_the_key_is_revoked(victim):
    _Victim.revoke_after = 3
    out = []
    result = attack.run(victim, "leaked", pages=30, delay=0, out=out.append, sleep=lambda s: None)
    assert result == {"revoked": True, "pages_fetched": 3, "revoked_after_s": result["revoked_after_s"]}
    assert len(_Victim.seen) == 4  # 3 ok, then the 401 that stops it; no page 5
    assert [r["page"] for r in _Victim.seen] == ["1", "2", "3", "4"]
    assert all(r["key"] == "leaked" and r["path"] == "/api/customers" for r in _Victim.seen)
    assert "-> 200" in out[0] and "-> 401" in out[3]
    assert "revoked after 3 page(s)" in out[-1]


def test_finishes_the_page_budget_when_never_revoked(victim):
    _Victim.revoke_after = 100
    result = attack.run(victim, "leaked", pages=5, delay=0, out=lambda line: None, sleep=lambda s: None)
    assert result == {"revoked": False, "pages_fetched": 5, "revoked_after_s": None}
    assert len(_Victim.seen) == 5


def test_waits_between_requests_but_not_after_the_last(victim):
    _Victim.revoke_after = 100
    waits = []
    attack.run(victim, "leaked", pages=4, delay=7, out=lambda line: None, sleep=waits.append)
    assert waits == [7, 7, 7]  # one gap between each pair, none trailing
