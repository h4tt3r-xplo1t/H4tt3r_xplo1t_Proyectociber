import importlib
import pyexpat

MIN_EXPAT = (2, 7, 2)


def test_package_and_dependencies_import():
    importlib.import_module("worker_noticias")
    importlib.import_module("defusedxml")
    importlib.import_module("urllib3")


def test_expat_is_recent_enough():
    # Older Expat releases are vulnerable to billion laughs, quadratic blowup
    # and large-token attacks (Python 3.14 xml docs).
    raw = pyexpat.EXPAT_VERSION
    parts = raw.removeprefix("expat_").split(".")
    assert len(parts) >= 3 and all(p.isdecimal() for p in parts[:3]), (
        f"unexpected Expat version format: {raw!r}"
    )
    parsed = tuple(int(part) for part in parts[:3])
    assert parsed >= MIN_EXPAT, f"Expat {raw!r} is older than {MIN_EXPAT}"
