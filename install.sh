#!/usr/bin/env bash
# Build piip and install it as a Claude Code skill.
#
#   ./install.sh                 # ~/.claude/skills/piip + ~/.local/bin/piip
#   ./install.sh --project DIR   # DIR/.claude/skills/piip (shared with a repo)
#   ./install.sh --no-link       # do not link piip into ~/.local/bin
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILLS_DIR="$HOME/.claude/skills"
LINK=1

while [[ $# -gt 0 ]]; do
	case "$1" in
	--project) SKILLS_DIR="$(cd "$2" && pwd)/.claude/skills"; shift 2 ;;
	--no-link) LINK=0; shift ;;
	*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
done

DEST="$SKILLS_DIR/piip"

echo "Building piip (release)..."
cargo build --release --quiet --manifest-path "$ROOT/Cargo.toml"

if [[ -e "$DEST" && ! -f "$DEST/SKILL.md" ]]; then
	echo "$DEST exists and is not a piip skill; refusing to overwrite." >&2
	exit 1
fi
if [[ -f "$DEST/SKILL.md" ]] && ! grep -q '^name: piip$' "$DEST/SKILL.md"; then
	echo "$DEST holds a different skill; refusing to overwrite." >&2
	exit 1
fi

rm -rf "$DEST"
mkdir -p "$DEST/bin" "$DEST/presidio"
cp -r "$ROOT/skill/piip/." "$DEST/"
cp "$ROOT/target/release/piip" "$DEST/bin/piip"
cp "$ROOT/presidio/pyproject.toml" "$ROOT/presidio/uv.lock" "$ROOT/presidio/server.py" "$DEST/presidio/"
chmod +x "$DEST/scripts/"*.sh

echo "Installed skill: $DEST"

if [[ $LINK -eq 1 ]]; then
	mkdir -p "$HOME/.local/bin"
	ln -sf "$DEST/bin/piip" "$HOME/.local/bin/piip"
	echo "Linked: $HOME/.local/bin/piip"
	case ":$PATH:" in
	*":$HOME/.local/bin:"*) ;;
	*) echo "Note: add ~/.local/bin to PATH to run piip directly." ;;
	esac
fi

echo "Optional deeper backend: bash $DEST/scripts/presidio-start.sh  (then: piip -e hybrid ...)"
