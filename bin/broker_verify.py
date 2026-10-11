#!/usr/bin/env python3
"""User verification: the gate that turns "present" into "verified".

A passkey sign-in is only worth anything if *someone who is allowed* approved it. The software
authenticator's key is on disk, so possession of the file is not enough — a live fingerprint
check is what proves the person at the keyboard is the owner. This module runs fprintd and
reports honestly what happened, distinguishing the three outcomes that matter:

  * verified     — the finger matched; the assertion may be signed with UV set
  * declined     — a finger was presented and did not match; the caller must refuse
  * unavailable  — fprintd is missing or errored; the caller decides (and by default refuses,
                   because "we could not check" must never be indistinguishable from "checked")
  * delegated    — set by the BROKER, not by fprintd: user verification was handed to the
                   credential's own authenticator (a FIDO2 token validating its PIN). It counts
                   exactly like ``verified`` — but no local sensor was involved, which is what
                   makes an attached security key usable on a machine whose fingerprint sensor
                   the owner cannot use.

The command runner is injectable so the whole policy can be tested without ever prompting a
real sensor.
"""
import shutil
import subprocess

# fprintd-verify exit codes (see its man page). Only 0 is success.
FPRINTD_PASS = 0
FPRINTD_FAIL = 1


class VerifyResult:
    def __init__(self, ok, state, detail=""):
        self.ok = ok            # may the caller proceed with UV set?
        self.state = state      # verified | declined | unavailable
        self.detail = detail

    def as_dict(self):
        return {"ok": self.ok, "state": self.state, "detail": self.detail}

    def __repr__(self):
        return "VerifyResult(%r, %r, %r)" % (self.ok, self.state, self.detail)


class FprintdVerifier:
    """User verification by fingerprint, via the system fprintd."""

    def __init__(self, username=None, runner=None, timeout=30):
        self.username = username
        self.timeout = timeout
        # runner(cmd) -> (returncode, stdout, stderr); defaults to the real subprocess call.
        self._runner = runner or self._run

    def _run(self, cmd):
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return 127, "", str(exc)
        return proc.returncode, proc.stdout, proc.stderr

    def available(self):
        return bool(shutil.which("fprintd-verify"))

    def verify(self, message=None):
        """Prompt for and check one fingerprint. Never raises for an ordinary failure."""
        if not self.available():
            return VerifyResult(False, "unavailable", "fprintd-verify not on PATH")
        cmd = ["fprintd-verify"]
        if self.username:
            cmd.append(self.username)
        code, out, err = self._runner(cmd)
        if code == FPRINTD_PASS:
            return VerifyResult(True, "verified", (out or "").strip())
        if code == FPRINTD_FAIL:
            # exit 1 = a finger was read and did not match: a real decline, not an outage.
            return VerifyResult(False, "declined", (err or out or "").strip())
        return VerifyResult(False, "unavailable",
                            "fprintd-verify exit %s: %s" % (code, (err or out).strip()))


class NullVerifier:
    """Testing / headless stand-in. Explicitly opted into; never a silent default for the
    daemon, because a passkey that verifies nobody is a passwordless login with the password
    removed."""

    def __init__(self, ok=True):
        self._ok = ok

    def available(self):
        return True

    def verify(self, message=None):
        return VerifyResult(self._ok, "verified" if self._ok else "declined", "null verifier")
