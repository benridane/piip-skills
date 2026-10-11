#!/usr/bin/env bash
# Build piip and install it as a Claude Code skill.
#
#   ./install.sh                 # ~/.claude/skills/piip + ~/.local/bin/piip
#   ./install.sh --project DIR   # DIR/.claude/skills/piip (shared with a repo)
#   ./install.sh --no-link       # do not link piip into ~/.local/bin
#   ./install.sh --hook          # also register the masking hook in ~/.claude/settings.json
#                                # (with --project: DIR/.claude/settings.json)
#
# As a Claude Code plugin instead (skill + hook, binary fetched on first use):
#   /plugin marketplace add benridane/piip-skills
#   /plugin install piip@piip
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLAUDE_DIR="$HOME/.claude"
LINK=1
HOOK=0

while [[ $# -gt 0 ]]; do
	case "$1" in
	--project) CLAUDE_DIR="$(cd "$2" && pwd)/.claude"; shift 2 ;;
	--no-link) LINK=0; shift ;;
	--hook) HOOK=1; shift ;;
	*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
done

DEST="$CLAUDE_DIR/skills/piip"

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
cp -r "$ROOT/skills/piip/." "$DEST/"
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

if [[ $HOOK -eq 1 ]]; then
	SETTINGS="$CLAUDE_DIR/settings.json"
	python3 - "$SETTINGS" "$DEST/bin/piip" <<'PY'
import json, os, sys
path, binary = sys.argv[1], sys.argv[2]
settings = json.load(open(path)) if os.path.exists(path) else {}
command = f'"{binary}" hook'
events = {
    "PostToolUse": "Read|Grep|Bash",
    "PreToolUse": "^(Edit|MultiEdit|Write|NotebookEdit|Bash|WebFetch|WebSearch|mcp__.*)$",
    "UserPromptSubmit": None,
}
for event, matcher in events.items():
    groups = settings.setdefault("hooks", {}).setdefault(event, [])
    for group in groups:
        group["hooks"] = [h for h in group.get("hooks", []) if not h.get("command", "").endswith('/piip" hook')]
    groups[:] = [g for g in groups if g["hooks"]]
    group = {"hooks": [{"type": "command", "command": command, "timeout": 120}]}
    if matcher:
        group["matcher"] = matcher
    groups.append(group)
os.makedirs(os.path.dirname(path), exist_ok=True)
with open(path, "w") as f:
    json.dump(settings, f, indent=2, ensure_ascii=False)
    f.write("\n")
PY
	echo "Hooks registered in $SETTINGS (PostToolUse, PreToolUse, UserPromptSubmit)"
fi

echo "Optional deeper backend: bash $DEST/scripts/presidio-start.sh  (then: piip -e hybrid ...)"
