#!/usr/bin/env python3
"""The credential store: one 0600 JSON file per credential.

Two backends store different things here. The software authenticator keeps its ES256 private
key in the record, so the file's mode is the only thing protecting it — hence 0600 and no
exceptions. The token backend keeps the key in the hardware and stores only the metadata
needed to find the credential again (rp_id plus the credential id), because a private key that
lives on a security key must never be written to disk "for convenience".
"""
import json
import os
import pathlib
import time

import broker_paths

# The record fields that are secret. Kept in one place so a future field can be reviewed
# deliberately rather than leaking by default when someone adds one.
SECRET_FIELDS = ("private_pem",)


def _atomic_write(path, text, mode=0o600):
    """Write via a temp file then rename, so a reader never sees a truncated record and the
    final file is created with the requested mode from the start (not chmod-ed afterwards,
    which would leave a window at the default umask).

    The open is inside the try so a failure to even CREATE the temp file (a read-only parent
    directory, say) still runs the cleanup and re-raises the real error rather than something
    the cleanup itself produced.
    """
    path = pathlib.Path(path)
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise
    os.replace(tmp, path)


class CredentialStore:
    def __init__(self, cred_dir=None):
        self.dir = pathlib.Path(cred_dir) if cred_dir else broker_paths.credentials_dir()

    def _path(self, cred_id):
        # cred_id is already the base64url string the browser uses; it is also the filename.
        # Reject anything that could escape the directory — a credential id comes from a page.
        if not cred_id or "/" in cred_id or "\\" in cred_id or cred_id in (".", ".."):
            raise ValueError("invalid credential id: %r" % (cred_id,))
        return self.dir / (cred_id + ".json")

    def save(self, record):
        broker_paths.ensure_dir(self.dir)
        record = dict(record)
        record.setdefault("created", time.time())
        record.setdefault("sign_count", 0)
        _atomic_write(self._path(record["cred_id"]), json.dumps(record, indent=2))
        return record

    def load(self, cred_id):
        try:
            path = self._path(cred_id)
        except ValueError:
            return None
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            return None

    def list(self):
        """Every credential, oldest first. A corrupt file is skipped rather than allowed to
        take down discovery — one bad record must not hide all the good ones."""
        if not self.dir.exists():
            return []
        out = []
        for path in sorted(self.dir.glob("*.json")):
            try:
                out.append(json.loads(path.read_text(encoding="utf-8")))
            except (ValueError, OSError):
                continue
        out.sort(key=lambda r: r.get("created", 0))
        return out

    def delete(self, cred_id):
        try:
            path = self._path(cred_id)
        except ValueError:
            return False
        if not path.exists():
            return False
        path.unlink()
        return True

    def for_rp(self, rp_id, allow_ids=None):
        """Credentials usable for an rp. ``allow_ids`` (base64url) is the page's
        allowCredentials list; an empty/None list means "any credential for this rp"."""
        allow = set(allow_ids) if allow_ids else None
        out = []
        for rec in self.list():
            if rec.get("rp_id") != rp_id:
                continue
            if allow is not None and rec.get("cred_id") not in allow:
                continue
            out.append(rec)
        return out
