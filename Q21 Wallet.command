#!/bin/sh
# ---------------------------------------------------------------------------
#  Q21 Wallet: double-click this file.
# ---------------------------------------------------------------------------
#
#  Why this file exists
#
#  `q21` waits to be told what to do: `init`, `mine`, `wallet`. Double-
#  clicking it therefore opened nothing useful. A first user ran into it, and
#  he was right: he expected an application.
#
#  This file tells it `wallet`, and nothing else.
#
#  What it no longer does
#
#  It used to carry twenty lines of preparation: detect that there was no
#  wallet, announce that a passphrase was about to be requested, run `init`,
#  wait for the user to confirm they had copied down a code shown in the
#  Terminal. All of that now happens in screens, when the browser opens; see
#  src/setup.rs.
#
#  What it does in addition, on macOS: remove the quarantine
#
#  Every file downloaded by a browser gets a quarantine mark from macOS, and
#  a non-notarized program carrying it is refused at launch with "is damaged
#  and can't be opened", a message that blames the file when nothing is
#  damaged. Notarizing would require an Apple Developer account, hence an
#  identity verified by Apple, which this project does not do. So the mark is
#  removed here, once, on the whole folder: this is exactly the step that
#  NETWORK.md asked users to do by hand in the Terminal, and there is no
#  reason to leave it to the user. `xattr` fails silently when there is
#  nothing to remove (Linux, or an archive opened from the Terminal) and the
#  launcher carries on.
#
#  This launcher itself carries the same mark, and macOS blocks it once:
#  "from an unidentified developer". That is the only step left to the user,
#  and it is documented in JOIN.md. Once allowed, everything else goes
#  through here.
# ---------------------------------------------------------------------------
cd "$(dirname "$0")" || exit 1

# Remove the quarantine on the whole folder, quietly if there is nothing to remove.
xattr -dr com.apple.quarantine . 2>/dev/null || true
# The archive keeps the execute permission; we set it again to be safe.
chmod +x ./q21 2>/dev/null || true

./q21 wallet
