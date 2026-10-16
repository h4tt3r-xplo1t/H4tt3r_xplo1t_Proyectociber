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
    version = pyexpat.EXPAT_VERSION.removeprefix("expat_")
    parsed = tuple(int(part) for part in version.split("."))
    assert parsed >= MIN_EXPAT
