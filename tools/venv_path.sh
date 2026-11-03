#!/bin/bash
# Where the daemon's private venv lives — deliberately NOT inside the plugin folder.
#
# An Omarchy plugin folder may contain no symlinks: `omarchy-plugin-validate` refuses them
# ("symlinks are not allowed inside a plugin folder: …/.venv/lib64"), and a venv always has one.
# With the venv inside, the installed checkout fails validation, so `omarchy plugin update` merges
# the new commit and then ROLLS BACK ("update of '…' failed validation; rolled back") — the plugin
# silently stops receiving updates, which is the exact failure this file exists to prevent. Inside
# the checkout it also dirtied the tree on every install (an untracked .venv, plus chmod'ed files
# the manager's fast-forward then refused).
#
# So it lives under the data dir: outside the checkout, per-user, backed up with the rest of the
# user's data. Overridable for tests (PASSKEY_BROKER_VENV) and for an operator who wants it
# elsewhere.
#
# Sourced by install.sh; also sourced directly by tests/shell/test_venv_path.sh.

# broker_venv_dir — print the venv path.
broker_venv_dir() {
  printf '%s\n' "${PASSKEY_BROKER_VENV:-${XDG_DATA_HOME:-$HOME/.local/share}/omarchy-passkey-broker/venv}"
}

# broker_legacy_venv <plugin-dir> — the pre-1.2.11 location, inside the plugin folder. install.sh
# removes it, because leaving it there keeps breaking validation.
broker_legacy_venv() {
  printf '%s\n' "${1%/}/.venv"
}