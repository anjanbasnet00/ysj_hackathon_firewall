"""Live Google Drive activity connector (Layer 2 — replaces synthetic logs).

Streams REAL file activity from your Google Drive via the Drive Activity API and
maps each event into the DOC_EVENT data contract so the existing behavioural
rules (securewatch.detect.doc_rules) score it unchanged.

On a personal account we can see your own create / edit / move / rename / delete
activity in near-real-time — enough for a live demo where you act on a file and
watch the alert appear. department/file_sensitivity are placeholders, so
detection is behaviour-only (off-hours / bulk burst / large transfer).

One-time setup (see README): a Google Cloud OAuth client saved as
`credentials.json` in the repo root. Works with a **Web** client (the Streamlit
app at http://localhost:8501 is the OAuth redirect) or a **Desktop** client.
The first successful auth caches `token.json` so later runs connect silently.

Streamlit usage (web client):
    gdrive.try_connect_cached()           # silent if token.json is valid
    url = gdrive.auth_url()               # show as a "Connect" link
    gdrive.exchange_code(code)            # on redirect back with ?code=...
    events, cursor = gdrive.poll_activity(since)
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

import pandas as pd

from securewatch.config import C
from securewatch.schemas import DOC_EVENT_COLUMNS

# Allow the OAuth redirect over http://localhost and tolerate Google returning
# extra granted scopes — both expected for a local Streamlit demo.
os.environ.setdefault("OAUTHLIB_INSECURE_TRANSPORT", "1")
os.environ.setdefault("OAUTHLIB_RELAX_TOKEN_SCOPE", "1")

# Where Google sends the user back. Must be a registered redirect URI on the
# OAuth client AND the address Streamlit serves on (default localhost:8501).
REDIRECT_URI = os.environ.get("SECUREWATCH_REDIRECT_URI", "http://localhost:8501")

# Read-only: activity feed + file metadata (for file size).
SCOPES = [
    "https://www.googleapis.com/auth/drive.activity.readonly",
    "https://www.googleapis.com/auth/drive.metadata.readonly",
]

CREDENTIALS_FILE = C.root / "credentials.json"
TOKEN_FILE = C.root / "token.json"

# Drive Activity primaryActionDetail key -> our action vocabulary.
_ACTION_MAP = {
    "create": "create",
    "edit": "edit",
    "move": "move",
    "rename": "rename",
    "delete": "delete",
    "restore": "restore",
    "permissionChange": "permission_change",
    "comment": "comment",
    "dlpChange": "dlp_change",
    "reference": "reference",
    "settingsChange": "settings_change",
    "appliedLabelChange": "label_change",
}

# Cached API service handles (built once per process).
_activity = None
_drive = None
_about_cache: dict | None = None   # connected account identity (email/name/photo)
_size_cache: dict[str, int] = {}


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
def credentials_present() -> bool:
    return CREDENTIALS_FILE.exists()


def is_connected() -> bool:
    return _activity is not None


def client_type() -> str:
    """'web' or 'installed' (desktop) — the top-level key in credentials.json."""
    with open(CREDENTIALS_FILE) as fh:
        return next(iter(json.load(fh)))


def _build_services(creds) -> None:
    """Build the Drive Activity + Drive API handles from valid credentials."""
    global _activity, _drive, _about_cache
    from googleapiclient.discovery import build
    _activity = build("driveactivity", "v2", credentials=creds, cache_discovery=False)
    _drive = build("drive", "v3", credentials=creds, cache_discovery=False)
    _about_cache = None  # force identity re-fetch for the (possibly new) account


def _require_credentials() -> None:
    if not credentials_present():
        raise FileNotFoundError(
            f"Missing {CREDENTIALS_FILE.name}. Create an OAuth client in Google "
            "Cloud Console, download it, and save it as credentials.json in the "
            "repo root. See the README 'Live Drive layer' section."
        )


def _cached_creds():
    """Load token.json, refreshing if expired. Returns valid Credentials or None."""
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials

    if not TOKEN_FILE.exists():
        return None
    creds = Credentials.from_authorized_user_file(str(TOKEN_FILE), SCOPES)
    if creds and creds.valid:
        return creds
    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())
        TOKEN_FILE.write_text(creds.to_json())
        return creds
    return None


def try_connect_cached() -> bool:
    """Connect silently if a valid cached token exists. Returns whether connected."""
    if _activity is not None:
        return True
    if not credentials_present():
        return False
    creds = _cached_creds()
    if creds is None:
        return False
    _build_services(creds)
    return True


def auth_url() -> str:
    """Build the Google consent URL for the web OAuth flow (redirect to Streamlit)."""
    _require_credentials()
    from google_auth_oauthlib.flow import Flow

    flow = Flow.from_client_secrets_file(
        str(CREDENTIALS_FILE), scopes=SCOPES, redirect_uri=REDIRECT_URI)
    # `select_account` forces Google's account chooser so the user can pick
    # WHICH Google account to connect (instead of silently reusing the last one).
    url, _ = flow.authorization_url(
        access_type="offline", include_granted_scopes="true",
        prompt="consent select_account")
    return url


def exchange_code(code: str) -> None:
    """Exchange the ?code= from Google's redirect for a token, cache it, connect."""
    _require_credentials()
    from google_auth_oauthlib.flow import Flow

    flow = Flow.from_client_secrets_file(
        str(CREDENTIALS_FILE), scopes=SCOPES, redirect_uri=REDIRECT_URI)
    flow.fetch_token(code=code)
    creds = flow.credentials
    TOKEN_FILE.write_text(creds.to_json())
    _build_services(creds)


def scan_files(max_files: int = 200) -> list[dict]:
    """Discover the files that EXIST in the Drive (newest first) and map each to
    a DOC_EVENT row, so the dashboard scans real files even with no recent
    activity. Folders are skipped; native Docs/Sheets report no size (0 bytes)."""
    if _drive is None:
        raise RuntimeError("Not connected — authenticate first.")

    events: list[dict] = []
    page_token = None
    while len(events) < max_files:
        resp = _drive.files().list(
            pageSize=min(100, max_files - len(events)),
            q="trashed=false",
            orderBy="modifiedTime desc",
            fields=("nextPageToken, files(id,name,size,modifiedTime,mimeType,"
                    "shared,owners(emailAddress,displayName))"),
            pageToken=page_token,
        ).execute()
        for f in resp.get("files", []):
            if f.get("mimeType") == "application/vnd.google-apps.folder":
                continue
            events.append(_file_to_event(f))
        page_token = resp.get("nextPageToken")
        if not page_token:
            break
    return events


def _file_to_event(f: dict) -> dict:
    raw = f.get("modifiedTime")
    ts = (pd.to_datetime(raw, utc=True).tz_localize(None)
          if raw else pd.Timestamp.now())
    owner = (f.get("owners") or [{}])[0]
    shared = bool(f.get("shared"))
    return {
        "timestamp": ts,
        "user_id": owner.get("emailAddress", "me"),
        "user_name": owner.get("displayName", "You"),
        "department": "Drive",
        "role": "user",
        "file_id": f.get("id", ""),
        "file_path": f.get("name", "(unnamed)"),
        "file_sensitivity": "shared" if shared else "unknown",
        "action": "shared file" if shared else "file",
        "bytes": int(f.get("size", 0) or 0),
        "ip_address": "",
        "hour": int(ts.hour),
    }


def account_info() -> dict:
    """Identity of the CURRENTLY-connected account: {email, name, photo}.

    Pulled live from the Drive API (reflects whichever account the active token
    belongs to) and cached per connection so we don't re-query every poll.
    """
    global _about_cache
    if _drive is None:
        return {"email": "", "name": "", "photo": ""}
    if _about_cache is not None:
        return _about_cache
    try:
        about = _drive.about().get(
            fields="user(emailAddress,displayName,photoLink)").execute()
        u = about.get("user", {})
        _about_cache = {
            "email": u.get("emailAddress", ""),
            "name": u.get("displayName", ""),
            "photo": u.get("photoLink", ""),
        }
    except Exception:
        _about_cache = {"email": "", "name": "", "photo": ""}
    return _about_cache


def account_email() -> str:
    """Back-compat: just the connected account's email."""
    return account_info()["email"]


def disconnect() -> None:
    """Sign out: drop API handles, clear caches, and delete the cached token so
    the next connect shows Google's account chooser (lets you SWITCH accounts)."""
    global _activity, _drive, _about_cache
    _activity = None
    _drive = None
    _about_cache = None
    _size_cache.clear()
    try:
        TOKEN_FILE.unlink(missing_ok=True)
    except Exception:
        pass


def connect_desktop() -> None:
    """Fallback for a Desktop OAuth client: open a browser via a local server."""
    if _activity is not None:
        return
    _require_credentials()
    from google_auth_oauthlib.flow import InstalledAppFlow

    creds = _cached_creds()
    if creds is None:
        flow = InstalledAppFlow.from_client_secrets_file(str(CREDENTIALS_FILE), SCOPES)
        creds = flow.run_local_server(port=0)
        TOKEN_FILE.write_text(creds.to_json())
    _build_services(creds)


# ---------------------------------------------------------------------------
# Polling
# ---------------------------------------------------------------------------
def poll_activity(since: datetime | None, max_items: int = 100) -> tuple[list[dict], datetime]:
    """Fetch Drive activity newer than `since`, mapped to DOC_EVENT rows.

    Returns (events, new_cursor). `new_cursor` is the latest event time seen
    (or `since`/now when there is nothing new) so the next poll continues cleanly.
    """
    if _activity is None:
        raise RuntimeError("Not connected — authenticate first.")

    body: dict = {"pageSize": max_items}
    if since is not None:
        # Drive Activity filter wants epoch milliseconds.
        ms = int(since.astimezone(timezone.utc).timestamp() * 1000)
        body["filter"] = f"time > {ms}"

    resp = _activity.activity().query(body=body).execute()
    activities = resp.get("activities", [])

    events: list[dict] = []
    newest = since
    for act in activities:
        ts = _activity_time(act)
        if ts is None:
            continue
        if newest is None or ts > newest:
            newest = ts
        events.extend(_to_events(act, ts))

    events.sort(key=lambda e: e["timestamp"])
    return events, (newest or since or datetime.now(timezone.utc))


def _activity_time(act: dict) -> datetime | None:
    raw = act.get("timestamp") or (act.get("timeRange") or {}).get("endTime")
    if not raw:
        return None
    return pd.to_datetime(raw, utc=True).to_pydatetime()


def _to_events(act: dict, ts: datetime) -> list[dict]:
    """One Drive activity -> one DOC_EVENT row per file target."""
    action = _action_name(act.get("primaryActionDetail", {}))
    actor_id, actor_name = _actor(act.get("actors", []))

    rows: list[dict] = []
    for target in act.get("targets", []):
        item = target.get("driveItem")
        if not item:
            continue  # skip non-file targets (drives, comments)
        file_id = item.get("name", "").replace("items/", "")
        rows.append({
            "timestamp": pd.Timestamp(ts).tz_localize(None),
            "user_id": actor_id,
            "user_name": actor_name,
            "department": "Drive",        # placeholder -> behaviour-only detection
            "role": "user",
            "file_id": file_id,
            "file_path": item.get("title", file_id),
            "file_sensitivity": "unknown",
            "action": action,
            "bytes": _file_size(file_id),
            "ip_address": "",
            "hour": ts.hour,
        })
    return rows


def _action_name(detail: dict) -> str:
    for key in detail:
        if key in _ACTION_MAP:
            return _ACTION_MAP[key]
    return "unknown"


def _actor(actors: list[dict]) -> tuple[str, str]:
    """Best-effort actor identity. Personal-account activity is usually 'you'."""
    for a in actors:
        user = a.get("user", {})
        known = user.get("knownUser", {})
        if known.get("isCurrentUser"):
            return ("me", "You")
        person = known.get("personName")
        if person:
            return (person, person)
    return ("unknown", "Unknown")


def _file_size(file_id: str) -> int:
    """File size in bytes (0 for native Docs/Sheets or on any error). Cached."""
    if not file_id or _drive is None:
        return 0
    if file_id in _size_cache:
        return _size_cache[file_id]
    size = 0
    try:
        meta = _drive.files().get(fileId=file_id, fields="size").execute()
        size = int(meta.get("size", 0))
    except Exception:
        size = 0
    _size_cache[file_id] = size
    return size


# Sanity: the row dict above must cover the data contract exactly.
assert set(DOC_EVENT_COLUMNS) == {
    "timestamp", "user_id", "user_name", "department", "role", "file_id",
    "file_path", "file_sensitivity", "action", "bytes", "ip_address", "hour",
}, "gdrive event keys drifted from DOC_EVENT_COLUMNS"
