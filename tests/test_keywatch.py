"""behavioral-signals A2: deterministic per-key baseline vs the current window."""
from datetime import datetime, timedelta, timezone

from conftest import SVC, load_module

kw = load_module("centinela_keywatch", SVC / "domain" / "keywatch.py")

CARACAS = timezone(timedelta(hours=-4))
NOW = datetime(2026, 10, 25, 15, 0, tzinfo=CARACAS)  # a Sunday afternoon
_ids = iter(range(1, 10_000_000))


def entry(ts: datetime, ip="203.0.113.1", path="/api/invoices", query=None, size=190, key=2, seed=False):
    return {"id": next(_ids), "ts": ts.timestamp(), "ip": ip, "method": "GET", "path": path, "query": query,
            "status": 200, "bytes": size, "api_key_id": key, "username": "ana", "lab_seed": seed}


def office_history(key=2):
    """Three weeks of weekday office-hours use from the office, two light endpoints."""
    out = []
    for day in range(1, 22):
        d = NOW - timedelta(days=day)
        if d.weekday() >= 5:
            continue
        for hour in (9, 11, 14, 16):
            ts = d.replace(hour=hour, minute=10)
            out.append(entry(ts, path="/api/me" if hour == 9 else "/api/invoices", key=key, seed=True))
    return out


def watch_with(history, tz_hours=-4):
    w = kw.KeyWatch(window_s=600, tz_offset_hours=tz_hours)
    w.ingest(history, now=NOW.timestamp())
    return w


def test_quiet_key_is_not_flagged():
    w = watch_with(office_history())
    assert w.evaluate(NOW.timestamp()) == []


def test_snowflake_pattern_is_flagged_with_every_signal():
    w = watch_with(office_history())
    attack = [entry(NOW - timedelta(seconds=300 - 10 * p), ip="198.51.100.23", path="/api/customers",
                    query=f"page={p}", size=4000) for p in range(1, 21)]
    w.ingest(attack, now=NOW.timestamp())
    [flag] = w.evaluate(NOW.timestamp())
    assert flag["key_id"] == 2
    s = flag["signals"]
    assert s["new_ip"] and s["new_network"] and s["off_hours"]
    assert s["new_endpoints"] == ["/api/customers"]
    assert s["pages"] == 20
    assert s["volume_ratio"] > 10
    assert flag["score"] >= 3
    assert flag["window"]["ips"] == ["198.51.100.23"]
    assert flag["window"]["bytes"] == 80_000
    assert flag["profile"]["networks"] == ["203.0.113.0/24"]
    assert flag["profile"]["days"] >= 14


def test_a_single_deviation_is_not_enough():
    """A known user travelling (new ip, usual endpoints, usual volume, office hours) is not flagged."""
    w = watch_with(office_history())
    monday = NOW + timedelta(days=1, hours=-4)  # Monday 11:00
    w.ingest([entry(monday - timedelta(seconds=60), ip="192.0.2.80")], now=monday.timestamp())
    assert w.evaluate(monday.timestamp()) == []


def test_anomalous_windows_are_not_learned_as_normal():
    w = watch_with(office_history())
    attack = [entry(NOW - timedelta(seconds=200 - p), ip="198.51.100.23", path="/api/customers",
                    query=f"page={p}", size=4000) for p in range(1, 11)]
    w.ingest(attack, now=NOW.timestamp())
    assert w.evaluate(NOW.timestamp())
    later = NOW + timedelta(hours=1)
    again = [entry(later - timedelta(seconds=100 - p), ip="198.51.100.23", path="/api/customers",
                   query=f"page={p}", size=4000) for p in range(1, 11)]
    w.ingest(again, now=later.timestamp())
    [flag] = w.evaluate(later.timestamp())
    assert flag["signals"]["new_ip"] is True  # the first attack did not become history


def test_failed_and_anonymous_requests_are_ignored():
    w = watch_with(office_history())
    noise = [dict(entry(NOW - timedelta(seconds=30), ip="198.51.100.23", path="/api/customers"), status=401),
             dict(entry(NOW - timedelta(seconds=20), ip="198.51.100.23"), api_key_id=None)]
    w.ingest(noise, now=NOW.timestamp())
    assert w.evaluate(NOW.timestamp()) == []


def test_skips_keys_listed_as_inactive():
    w = watch_with(office_history())
    w.ingest([entry(NOW - timedelta(seconds=300 - 10 * p), ip="198.51.100.23", path="/api/customers",
                    query=f"page={p}", size=4000) for p in range(1, 21)], now=NOW.timestamp())
    assert w.evaluate(NOW.timestamp(), active_keys={3}) == []


def test_recent_activity_is_judged_not_learned_even_after_a_restart():
    """A restart re-reads the whole log; today's attack must not come back as history."""
    earlier = [entry(NOW - timedelta(hours=1, seconds=p), ip="198.51.100.23", path="/api/customers",
                     query=f"page={p}", size=4000) for p in range(1, 21)]
    w = watch_with(office_history() + earlier)  # a fresh KeyWatch, as after a redeploy
    again = [entry(NOW - timedelta(seconds=100 - p), ip="198.51.100.23", path="/api/customers",
                   query=f"page={p}", size=4000) for p in range(1, 11)]
    w.ingest(again, now=NOW.timestamp())
    [flag] = w.evaluate(NOW.timestamp())
    assert flag["signals"]["new_ip"] and flag["signals"]["new_endpoints"] == ["/api/customers"]
    assert flag["profile"]["endpoints"] == ["/api/invoices", "/api/me"]
