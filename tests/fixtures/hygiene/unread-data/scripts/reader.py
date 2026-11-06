"""Known-bad fixture reader: reads used.json, the profile under profiles/ and the reports register."""
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
USED = REPO / "data" / "used.json"
PROFILE = REPO / "data" / "profiles" / "profile.json"
REGISTER = REPO / "data" / "reports" / "register.json"
