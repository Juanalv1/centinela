"""The victim image copies an explicit file list: every module it imports must be in it."""
from conftest import VICTIM


def test_every_victim_module_is_copied_into_the_image():
    copied = set()
    for line in (VICTIM / "Dockerfile").read_text().splitlines():
        if line.startswith("COPY "):
            copied.update(line.split()[1:-1])
    missing = sorted(p.name for p in VICTIM.glob("*.py") if p.name not in copied)
    assert not missing, f"add to victim/Dockerfile COPY: {missing}"
