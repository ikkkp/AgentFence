#!/usr/bin/env sh
set -eu

INSTALL_DIR="${AGENTFENCE_INSTALL_DIR:-"$HOME/.local/bin"}"
PACKAGE_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

if [ ! -f "$PACKAGE_DIR/agentfence" ] || [ ! -f "$PACKAGE_DIR/agentfenced" ]; then
  echo "Run this script from an AgentFence release archive containing agentfence and agentfenced." >&2
  exit 1
fi

mkdir -p "$INSTALL_DIR"
install -m 755 "$PACKAGE_DIR/agentfence" "$INSTALL_DIR/agentfence"
install -m 755 "$PACKAGE_DIR/agentfenced" "$INSTALL_DIR/agentfenced"

case ":$PATH:" in
  *":$INSTALL_DIR:"*)
    echo "$INSTALL_DIR is already on PATH."
    ;;
  *)
    PROFILE="${AGENTFENCE_PROFILE:-"$HOME/.profile"}"
    {
      echo ""
      echo "# AgentFence CLI"
      echo "export PATH='$INSTALL_DIR':\"\$PATH\""
    } >> "$PROFILE"
    echo "Added $INSTALL_DIR to $PROFILE. Open a new terminal before running agentfence."
    ;;
esac

echo "Installed AgentFence CLI to $INSTALL_DIR"
