"""Regenerate pinned_requirements.txt from uv.lock (run when uv.lock changes).

    python test_data/gen_pinned.py

One `name==version` line per registry package, PEP 503 deduped so pip-audit's
--no-deps (which rejects duplicate requirements) accepts the file.
"""

import re
import tomllib
from pathlib import Path

HERE = Path(__file__).parent


def main() -> None:
    lock = tomllib.load((HERE / "uv.lock").open("rb"))
    seen: dict[str, str] = {}
    for pkg in lock["package"]:
        if "version" not in pkg or "registry" not in pkg.get("source", {}):
            continue  # skip the root project, path deps, and editable installs
        key = re.sub(r"[-_.]+", "-", pkg["name"].lower())  # PEP 503 normalize
        seen.setdefault(key, f"{pkg['name']}=={pkg['version']}")

    lines = sorted(seen.values(), key=str.lower)
    (HERE / "pinned_requirements.txt").write_text("\n".join(lines) + "\n")
    print(f"wrote {len(lines)} pinned packages")


if __name__ == "__main__":
    main()
