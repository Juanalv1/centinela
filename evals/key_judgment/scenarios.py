"""Hand-written key-judgment scenarios: a per-key profile, the current window, and the expected call.

The profile mirrors what centinela's KeyWatch learns per key (networks, weekdays,
hour range, endpoints, busiest hour), plus who owns the key and the resources
(accounts, tenants, stores) it has touched. Times are naive local time.
The week used is Mon 2026-10-19 .. Sun 2026-10-25; month-end cases use Sep 30 / Oct 31.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

ALL_DAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
WORKDAYS = ALL_DAYS[:5]

# family -> expected label
FAMILIES = {
    "travel": "allow",
    "new_integration": "allow",
    "month_end": "allow",
    "infra_change": "allow",
    "weekend_oncall": "allow",
    "bulk_export": "revoke",
    "low_and_slow": "revoke",
    "mimic": "revoke",
    "off_hours_scrape": "revoke",
}


@dataclass(frozen=True)
class Profile:
    owner: str  # "person" or "machine" (an integration)
    networks: tuple[str, ...]  # CIDRs the key was used from
    weekdays: tuple[str, ...]
    hours: tuple[int, int]  # first and last usual local hour, inclusive
    endpoints: tuple[str, ...]
    typical_hour_requests: int
    max_hour_requests: int
    max_hour_bytes: int
    history_days: int
    resources: tuple[str, ...] = ()  # resource scopes touched so far; empty = not tracked


@dataclass(frozen=True)
class Request:
    time: datetime
    ip: str
    endpoint: str
    page: int | None
    bytes: int
    resource: str | None = None


@dataclass(frozen=True)
class Scenario:
    id: str
    family: str
    expected: str  # "revoke" or "allow"
    description: str
    profile: Profile
    window: tuple[Request, ...]
    hard: bool = False


def series(start: str, count: int, every_s: int, ip: str, endpoints, size: int, *,
           paged: bool = False, first_page: int = 1, resources=None) -> list[Request]:
    """`count` requests from `start` every ~`every_s` seconds, cycling endpoints and resources.
    Gaps and sizes get a small deterministic jitter so the window does not look synthetic."""
    t0 = datetime.fromisoformat(start)
    eps = (endpoints,) if isinstance(endpoints, str) else tuple(endpoints)
    res = (resources,) if isinstance(resources, str) or resources is None else tuple(resources)
    out = []
    for i in range(count):
        jitter = (i * 13) % max(1, every_s // 4)
        out.append(Request(
            time=t0 + timedelta(seconds=i * every_s + jitter),
            ip=ip,
            endpoint=eps[i % len(eps)],
            page=first_page + i if paged else None,
            bytes=size + (i * 211) % (size // 5 + 1),
            resource=res[i % len(res)],
        ))
    return out


def window(*parts: list[Request]) -> tuple[Request, ...]:
    return tuple(sorted((r for p in parts for r in p), key=lambda r: r.time))


# ---- profiles reused across families ---------------------------------------------------------

ACCOUNTANT = Profile(  # Ana, accounts payable; office CANTV line plus home
    owner="person", networks=("190.202.14.0/24", "186.88.60.0/24"), weekdays=WORKDAYS, hours=(8, 18),
    endpoints=("/api/invoices", "/api/invoices/{id}", "/api/me"),
    typical_hour_requests=25, max_hour_requests=60, max_hour_bytes=1_800_000, history_days=90,
    resources=("company:farmacia-sur",))

ERP_SYNC = Profile(  # ERP integration running on a GCP VM, around the clock
    owner="machine", networks=("34.95.120.0/24",), weekdays=ALL_DAYS, hours=(0, 23),
    endpoints=("/api/invoices", "/api/payments"),
    typical_hour_requests=120, max_hour_requests=180, max_hour_bytes=6_000_000, history_days=160,
    resources=("tenant:acme",))

BI_CONNECTOR = Profile(  # nightly BI batch on AWS sa-east-1
    owner="machine", networks=("52.67.88.0/24",), weekdays=ALL_DAYS, hours=(1, 5),
    endpoints=("/api/sales/daily",),
    typical_hour_requests=20, max_hour_requests=40, max_hour_bytes=400_000, history_days=120)

SALES_REP = Profile(  # field sales, office plus home
    owner="person", networks=("200.44.32.0/24", "186.92.14.0/24"), weekdays=WORKDAYS, hours=(8, 18),
    endpoints=("/api/customers", "/api/customers/{id}", "/api/orders"),
    typical_hour_requests=40, max_hour_requests=90, max_hour_bytes=2_500_000, history_days=300)


def _travel() -> list[Scenario]:
    return [
        Scenario(
            "travel-1", "travel", "allow",
            "Accountant at a conference in Madrid checks a few invoices at 23:10 local from a Spanish ISP.",
            ACCOUNTANT,
            window(series("2026-10-20T23:10:00", 18, 95, "88.27.140.15",
                          ("/api/invoices", "/api/invoices/{id}", "/api/invoices/{id}"), 6_500,
                          resources="company:farmacia-sur"))),
        Scenario(
            "travel-2", "travel", "allow",
            "Sales rep at an airport before a 7am flight reviews customers and orders over a US mobile carrier.",
            Profile(owner="person", networks=("200.44.32.0/24",), weekdays=WORKDAYS, hours=(9, 17),
                    endpoints=("/api/customers", "/api/customers/{id}", "/api/orders"),
                    typical_hour_requests=40, max_hour_requests=90, max_hour_bytes=2_500_000, history_days=200),
            window(series("2026-10-22T06:05:00", 3, 40, "172.58.12.77", "/api/customers", 21_000, paged=True),
                   series("2026-10-22T06:09:00", 29, 85, "172.58.12.77",
                          ("/api/customers/{id}", "/api/orders", "/api/customers/{id}"), 4_800))),
        Scenario(
            "travel-3", "travel", "allow",
            "Owner on a Saturday at a hotel lists eight pages of invoices to prepare a client meeting.",
            Profile(owner="person", networks=("190.202.14.0/24", "186.88.60.0/24"), weekdays=WORKDAYS,
                    hours=(8, 19), endpoints=("/api/reports/monthly", "/api/invoices"),
                    typical_hour_requests=12, max_hour_requests=30, max_hour_bytes=900_000, history_days=400),
            window(series("2026-10-24T14:00:00", 8, 70, "81.169.200.33", "/api/invoices", 22_000, paged=True),
                   series("2026-10-24T14:12:00", 18, 120, "81.169.200.33",
                          ("/api/reports/monthly", "/api/invoices"), 9_000)),
            hard=True),
    ]


def _new_integration() -> list[Scenario]:
    return [
        Scenario(
            "new_integration-1", "new_integration", "allow",
            "ERP sync starts pushing credit notes: same VM, same cadence, a handful of calls to a new endpoint.",
            ERP_SYNC,
            window(series("2026-10-21T10:00:00", 40, 45, "34.95.120.18", ("/api/invoices", "/api/payments"),
                          11_000, resources="tenant:acme"),
                   series("2026-10-21T10:05:30", 6, 240, "34.95.120.18", "/api/credit-notes", 3_200,
                          resources="tenant:acme"))),
        Scenario(
            "new_integration-2", "new_integration", "allow",
            "Developer wires up webhooks from the office during work hours, plus a few usual product calls.",
            Profile(owner="person", networks=("200.71.80.0/24",), weekdays=WORKDAYS, hours=(9, 18),
                    endpoints=("/api/products", "/api/products/{id}"),
                    typical_hour_requests=30, max_hour_requests=70, max_hour_bytes=1_200_000, history_days=60),
            window(series("2026-10-20T15:00:00", 14, 160, "200.71.80.23", ("/api/webhooks", "/api/webhooks/{id}"),
                          1_400),
                   series("2026-10-20T15:03:00", 5, 400, "200.71.80.23", "/api/products/{id}", 5_600))),
        Scenario(
            "new_integration-3", "new_integration", "allow",
            "BI connector adds a customer dimension: same IP and nightly slot, backfills 14 pages of customers.",
            BI_CONNECTOR,
            window(series("2026-10-21T02:00:00", 4, 60, "52.67.88.41", "/api/sales/daily", 18_000),
                   series("2026-10-21T02:06:00", 14, 75, "52.67.88.41", "/api/customers", 45_000, paged=True)),
            hard=True),
    ]


def _month_end() -> list[Scenario]:
    return [
        Scenario(
            "month_end-1", "month_end", "allow",
            "Month-end close: accountant reviews ~160 invoices in one afternoon hour from the office.",
            Profile(owner="person", networks=("190.202.14.0/24",), weekdays=WORKDAYS, hours=(8, 18),
                    endpoints=("/api/invoices", "/api/invoices/{id}", "/api/reports/monthly"),
                    typical_hour_requests=30, max_hour_requests=70, max_hour_bytes=2_000_000, history_days=300),
            window(series("2026-09-30T16:00:00", 156, 22, "190.202.14.52", "/api/invoices/{id}", 6_200),
                   series("2026-09-30T16:40:00", 4, 300, "190.202.14.52", "/api/reports/monthly", 48_000))),
        Scenario(
            "month_end-2", "month_end", "allow",
            "Billing job's first month-end run since it was deployed 26 days ago: lists every invoice of the month.",
            Profile(owner="machine", networks=("35.199.80.0/24",), weekdays=ALL_DAYS, hours=(0, 23),
                    endpoints=("/api/invoices", "/api/payments"),
                    typical_hour_requests=180, max_hour_requests=300, max_hour_bytes=9_000_000, history_days=26),
            window(series("2026-09-30T23:00:00", 40, 30, "35.199.80.7", "/api/invoices", 60_000, paged=True),
                   series("2026-09-30T23:01:00", 900, 3, "35.199.80.7", "/api/payments", 2_100))),
        Scenario(
            "month_end-3", "month_end", "allow",
            "CFO assistant closes October from home on Saturday the 31st: 60 invoice pages plus reports.",
            Profile(owner="person", networks=("200.44.32.0/24", "186.88.61.0/24"), weekdays=WORKDAYS,
                    hours=(8, 18), endpoints=("/api/invoices", "/api/reports/monthly", "/api/payments"),
                    typical_hour_requests=15, max_hour_requests=35, max_hour_bytes=1_500_000, history_days=45),
            window(series("2026-10-31T10:00:00", 60, 100, "186.88.61.40", "/api/invoices", 30_000, paged=True),
                   series("2026-10-31T10:05:00", 120, 55, "186.88.61.40", ("/api/payments", "/api/reports/monthly"),
                          4_000)),
            hard=True),
    ]


def _infra_change() -> list[Scenario]:
    return [
        Scenario(
            "infra_change-1", "infra_change", "allow",
            "Webhook relay migrated to a new AWS range: same endpoints and rate, new source IP.",
            Profile(owner="machine", networks=("52.14.30.0/24",), weekdays=ALL_DAYS, hours=(0, 23),
                    endpoints=("/api/orders", "/api/orders/{id}"),
                    typical_hour_requests=300, max_hour_requests=520, max_hour_bytes=4_000_000, history_days=210),
            window(series("2026-10-22T13:00:00", 95, 12, "3.142.77.201", ("/api/orders/{id}", "/api/orders"), 3_300))),
        Scenario(
            "infra_change-2", "infra_change", "allow",
            "Nightly ETL moved from GCP to Azure and its scheduler now fires at 06:00 instead of 02:00.",
            Profile(owner="machine", networks=("104.196.10.0/24",), weekdays=WORKDAYS, hours=(2, 4),
                    endpoints=("/api/sales/daily", "/api/inventory"),
                    typical_hour_requests=60, max_hour_requests=90, max_hour_bytes=3_000_000, history_days=180),
            window(series("2026-10-23T06:00:00", 55, 30, "20.98.112.9", ("/api/sales/daily", "/api/inventory"),
                          26_000))),
        Scenario(
            "infra_change-3", "infra_change", "allow",
            "CI moved to a new runner pool and a weekend regression suite pages through products at 03:00.",
            Profile(owner="machine", networks=("140.82.112.0/24",), weekdays=WORKDAYS, hours=(9, 19),
                    endpoints=("/api/health", "/api/products"),
                    typical_hour_requests=10, max_hour_requests=25, max_hour_bytes=600_000, history_days=90),
            window(series("2026-10-24T03:00:00", 6, 20, "13.89.44.120", "/api/products", 15_000, paged=True),
                   series("2026-10-24T03:02:30", 14, 25, "13.89.44.120", ("/api/health", "/api/products"), 900)),
            hard=True),
    ]


def _weekend_oncall() -> list[Scenario]:
    return [
        Scenario(
            "weekend_oncall-1", "weekend_oncall", "allow",
            "SRE on call checks status and a few orders at 02:30 Sunday from their known home network.",
            Profile(owner="person", networks=("200.71.80.0/24", "186.92.14.0/24"), weekdays=WORKDAYS, hours=(8, 18),
                    endpoints=("/api/status", "/api/orders", "/api/orders/{id}"),
                    typical_hour_requests=20, max_hour_requests=50, max_hour_bytes=800_000, history_days=150),
            window(series("2026-10-25T02:30:00", 30, 90, "186.92.14.66", ("/api/status", "/api/orders/{id}"), 2_400))),
        Scenario(
            "weekend_oncall-2", "weekend_oncall", "allow",
            "Support lead handles an escalated refund on Saturday night, tethered to a mobile phone.",
            Profile(owner="person", networks=("200.44.32.0/24",), weekdays=WORKDAYS, hours=(9, 18),
                    endpoints=("/api/orders", "/api/orders/{id}", "/api/refunds"),
                    typical_hour_requests=25, max_hour_requests=60, max_hour_bytes=900_000, history_days=70),
            window(series("2026-10-24T21:00:00", 22, 110, "181.208.5.33", ("/api/orders/{id}", "/api/refunds"),
                          3_100))),
        Scenario(
            "weekend_oncall-3", "weekend_oncall", "allow",
            "Payment incident at 01:00 Sunday: on-call engineer at home pages failed payments and retries them.",
            Profile(owner="person", networks=("200.71.80.0/24", "186.92.14.0/24"), weekdays=WORKDAYS, hours=(8, 18),
                    endpoints=("/api/orders", "/api/orders/{id}", "/api/payments", "/api/payments/{id}"),
                    typical_hour_requests=20, max_hour_requests=45, max_hour_bytes=1_000_000, history_days=200),
            window(series("2026-10-25T01:00:00", 12, 50, "186.92.14.66", "/api/payments", 24_000, paged=True),
                   series("2026-10-25T01:12:00", 40, 45, "186.92.14.66", "/api/payments/{id}", 2_700),
                   series("2026-10-25T01:20:00", 8, 240, "186.92.14.66", "/api/payments/retry", 900)),
            hard=True),
    ]


def _bulk_export() -> list[Scenario]:
    return [
        Scenario(
            "bulk_export-1", "bulk_export", "revoke",
            "Leaked accountant key used from a VPS: 120 pages of a customer export in seven minutes.",
            ACCOUNTANT,
            window(series("2026-10-20T14:05:00", 120, 3, "45.137.21.9", "/api/export/customers", 220_000,
                          paged=True))),
        Scenario(
            "bulk_export-2", "bulk_export", "revoke",
            "ERP key replayed from a Tor exit: pages through customers and every invoice.",
            ERP_SYNC,
            window(series("2026-10-21T11:00:00", 80, 8, "185.220.101.4", "/api/customers", 95_000, paged=True,
                          resources="tenant:acme"),
                   series("2026-10-21T11:02:00", 60, 10, "185.220.101.4", "/api/invoices", 120_000, paged=True,
                          resources="tenant:acme"))),
        Scenario(
            "bulk_export-3", "bulk_export", "revoke",
            "Infostealer on the rep's home laptop pages 45 customer pages through the usual endpoint.",
            SALES_REP,
            window(series("2026-10-22T16:00:00", 45, 40, "186.92.14.21", "/api/customers", 180_000, paged=True)),
            hard=True),
    ]


def _low_and_slow() -> list[Scenario]:
    return [
        Scenario(
            "low_and_slow-1", "low_and_slow", "revoke",
            "Residential proxy pages customers every 5 minutes through the whole workday.",
            Profile(owner="person", networks=("190.202.14.0/24",), weekdays=WORKDAYS, hours=(8, 18),
                    endpoints=("/api/customers", "/api/customers/{id}"),
                    typical_hour_requests=30, max_hour_requests=70, max_hour_bytes=3_000_000, history_days=180),
            window(series("2026-10-21T09:00:00", 72, 300, "102.129.143.20", "/api/customers", 25_000, paged=True))),
        Scenario(
            "low_and_slow-2", "low_and_slow", "revoke",
            "Same cloud region, different subnet: BI key slowly pages customers inside its nightly slot.",
            Profile(owner="machine", networks=("52.67.88.0/24",), weekdays=ALL_DAYS, hours=(1, 5),
                    endpoints=("/api/sales/daily", "/api/customers"),
                    typical_hour_requests=20, max_hour_requests=40, max_hour_bytes=400_000, history_days=120),
            window(series("2026-10-22T01:00:00", 48, 300, "18.231.40.77", "/api/customers", 8_000, paged=True))),
        Scenario(
            "low_and_slow-3", "low_and_slow", "revoke",
            "Datacenter IP fetches one invoice every ~10 minutes for eight hours; the owner works in short bursts.",
            Profile(owner="person", networks=("190.202.14.0/24", "186.88.60.0/24"), weekdays=WORKDAYS, hours=(8, 18),
                    endpoints=("/api/invoices", "/api/invoices/{id}"),
                    typical_hour_requests=20, max_hour_requests=50, max_hour_bytes=1_500_000, history_days=250),
            window(series("2026-10-19T09:00:00", 48, 600, "5.188.62.140", "/api/invoices/{id}", 6_400)),
            hard=True),
    ]


def _mimic() -> list[Scenario]:
    return [
        Scenario(
            "mimic-1", "mimic", "revoke",
            "ERP key from a neighbouring GCP subnet, usual endpoints and rate, but reading other tenants.",
            ERP_SYNC,
            window(series("2026-10-21T10:00:00", 50, 36, "35.247.10.88", ("/api/invoices", "/api/payments"), 10_500,
                          resources=("tenant:globex", "tenant:initech", "tenant:umbrella")))),
        Scenario(
            "mimic-2", "mimic", "revoke",
            "Accountant key at 10am from a new IP: a few own-company calls, then two companies never touched.",
            ACCOUNTANT,
            window(series("2026-10-20T10:00:00", 5, 60, "190.140.22.13", ("/api/invoices", "/api/invoices/{id}"), 6_000,
                          resources="company:farmacia-sur"),
                   series("2026-10-20T10:06:00", 20, 100, "190.140.22.13", ("/api/invoices", "/api/invoices/{id}"),
                          6_000, resources=("company:distribuidora-norte", "company:agro-llanos")))),
        Scenario(
            "mimic-3", "mimic", "revoke",
            "From the office network itself, in hours, usual endpoints, but reading stores the key never touched.",
            Profile(owner="person", networks=("200.44.32.0/24",), weekdays=WORKDAYS, hours=(9, 17),
                    endpoints=("/api/orders", "/api/orders/{id}"),
                    typical_hour_requests=25, max_hour_requests=60, max_hour_bytes=1_200_000, history_days=140,
                    resources=("store:caracas-01", "store:caracas-02")),
            window(series("2026-10-22T11:00:00", 30, 60, "200.44.32.77", ("/api/orders", "/api/orders/{id}"), 5_200,
                          resources=("store:maracaibo-04", "store:valencia-02", "store:barquisimeto-01"))),
            hard=True),
    ]


def _off_hours_scrape() -> list[Scenario]:
    return [
        Scenario(
            "off_hours_scrape-1", "off_hours_scrape", "revoke",
            "Sunday 03:00 from a VPS: 150 customer pages plus detail calls in 25 minutes.",
            SALES_REP,
            window(series("2026-10-25T03:00:00", 150, 8, "45.95.169.12", "/api/customers", 40_000, paged=True),
                   series("2026-10-25T03:05:00", 60, 20, "45.95.169.12", "/api/customers/{id}", 4_500))),
        Scenario(
            "off_hours_scrape-2", "off_hours_scrape", "revoke",
            "BI key at 13:00 (outside its nightly slot) from a budget VPS: dumps 90 pages of sales history.",
            BI_CONNECTOR,
            window(series("2026-10-20T13:00:00", 90, 20, "23.94.5.150", "/api/sales/daily", 70_000, paged=True))),
        Scenario(
            "off_hours_scrape-3", "off_hours_scrape", "revoke",
            "Saturday 23:00 from the owner's known home network: 30 invoice pages at a steady pace.",
            ACCOUNTANT,
            window(series("2026-10-24T23:00:00", 30, 100, "186.88.60.9", "/api/invoices", 22_000, paged=True,
                          resources="company:farmacia-sur")),
            hard=True),
    ]


SCENARIOS: tuple[Scenario, ...] = tuple(
    _travel() + _new_integration() + _month_end() + _infra_change() + _weekend_oncall()
    + _bulk_export() + _low_and_slow() + _mimic() + _off_hours_scrape())


def by_id(scenario_id: str) -> Scenario:
    return next(s for s in SCENARIOS if s.id == scenario_id)
