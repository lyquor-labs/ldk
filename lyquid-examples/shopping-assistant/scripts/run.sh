#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXAMPLE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
EXAMPLES_DIR="$(cd "$EXAMPLE_DIR/.." && pwd)"
LDK_DIR="$(cd "$EXAMPLES_DIR/.." && pwd)"
REPO_DIR="$(cd "$LDK_DIR/.." && pwd)"
FLOW_UI_DIR="${FLOW_UI_DIR:-$REPO_DIR/ui}"

MODEL_PROVIDER="${MODEL_PROVIDER:-}"
if [[ -z "$MODEL_PROVIDER" ]]; then
    if [[ -n "${OPENAI_API_KEY:-}" ]]; then
        MODEL_PROVIDER="openai"
    elif [[ -n "${GEMINI_API_KEY:-}" ]]; then
        MODEL_PROVIDER="gemini"
    else
        echo "Set OPENAI_API_KEY or GEMINI_API_KEY." >&2
        exit 1
    fi
fi
case "$MODEL_PROVIDER" in
    openai) MODEL_API_KEY="${OPENAI_API_KEY:?Set OPENAI_API_KEY when MODEL_PROVIDER=openai.}" ;;
    gemini) MODEL_API_KEY="${GEMINI_API_KEY:?Set GEMINI_API_KEY when MODEL_PROVIDER=gemini.}" ;;
    *)
        echo "MODEL_PROVIDER must be openai or gemini." >&2
        exit 1
        ;;
esac

if [[ ! -f "$FLOW_UI_DIR/package.json" ]]; then
    echo "Set FLOW_UI_DIR to the shared ui/ package from the Lyquor repository." >&2
    exit 1
fi
command -v npm >/dev/null || { echo "The shared Flow page requires Node.js 22.12+ and npm." >&2; exit 1; }
if [[ ! -d "$FLOW_UI_DIR/node_modules" ]]; then
    npm --prefix "$FLOW_UI_DIR" ci
fi
npm --prefix "$FLOW_UI_DIR" run build

export RUSTUP_TOOLCHAIN=1.99.0
if [[ -n "${LYQUOR_BIN_DIR:-}" ]]; then
    # demo_require_tools adds this directory to PATH before starting the localnet.
    echo "Using native tools from $LYQUOR_BIN_DIR."
elif [[ -f "$REPO_DIR/Cargo.toml" &&
        -f "$REPO_DIR/toolchain/shaker/Cargo.toml" &&
        -f "$REPO_DIR/platform/node/Cargo.toml" ]]; then
    SHAKER_BIN="$REPO_DIR/target/debug/shaker"
    LYQUOR_BIN="$REPO_DIR/target/debug/lyquor"
    if [[ "${REBUILD_TOOLS:-0}" == "1" || ! -x "$SHAKER_BIN" || ! -x "$LYQUOR_BIN" ]]; then
        (
            cd "$REPO_DIR"
            cargo build --locked \
                --manifest-path "$REPO_DIR/Cargo.toml" \
                --package shaker --bin shaker \
                --package lyquor-node --bin lyquor
        )
    else
        echo "Reusing existing native tools in $REPO_DIR/target/debug."
    fi
    PATH="$REPO_DIR/target/debug:$PATH"
    export PATH
elif [[ "${REBUILD_TOOLS:-0}" == "1" ]]; then
    echo "REBUILD_TOOLS=1 requires a Lyquor monorepo checkout; use installed tools from PATH or LYQUOR_BIN_DIR." >&2
    exit 1
else
    echo "Using installed native tools from PATH."
fi

# shellcheck source=../../scripts/lib/demo.sh
. "$EXAMPLES_DIR/scripts/lib/demo.sh"

demo_start_localnet single
demo_deploy "shopping-assistant" "$EXAMPLE_DIR/Cargo.toml"
demo_wait_for_lyquid "flow_service_ready() returns (bool)"

demo_expect_true \
    "$(demo_call "set_model_api_key(string,string) returns (bool)" "$MODEL_PROVIDER" "$MODEL_API_KEY")" \
    "set model API key"

echo
echo "Shopping Assistant is available at http://127.0.0.1:8080/."
echo "Press Ctrl-C to stop the app and its localnet."

demo_run_foreground node "$FLOW_UI_DIR/scripts/serve.mjs" \
    --upstream http://127.0.0.1:8081 --port 8080 -- \
    shaker serve "$LYQUID_ID" --endpoint "$DEMO_PRIMARY_WS" --listen 127.0.0.1:8081
