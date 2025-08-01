#!/usr/bin/env bash
set -euo pipefail

# Shakenup - Lyquor development environment setup
FOUNDRY_VERSION="stable"

# Colors and logging
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${BOLD}${BLUE}==>${NC}${BOLD} $1${NC}"; }

ask_user() {
    local prompt="$1" default="${2:-yes}" response
    read -p "$prompt $([[ "$default" == "yes" ]] && echo "[Y/n]" || echo "[y/N]"): " response
    [[ "${response:-$([[ "$default" == "yes" ]] && echo "y" || echo "n")}" =~ ^[yY] ]]
}

detect_platform() {
    local format="${1:-foundry}" os=$(uname -s) arch=$(uname -m)
    # Normalize FreeBSD amd64 to x86_64
    [[ "$arch" == "amd64" ]] && arch="x86_64"
    
    # Detect WSL
    if [[ "$os" == "Linux" ]] && grep -qi "microsoft\|wsl" /proc/version 2>/dev/null; then
        log_info "WSL detected, using Linux binaries" >&2
    fi
    
    local sep="_"; [[ "$format" != "foundry" ]] && sep="-"
    
    case "$os-$arch" in
        Linux-x86_64) echo "linux${sep}amd64" ;;
        Linux-aarch64) echo "linux${sep}arm64" ;;
        Darwin-x86_64) echo "darwin${sep}amd64" ;;
        Darwin-arm64) echo "darwin${sep}arm64" ;;
        *BSD-x86_64|FreeBSD-x86_64|NetBSD-x86_64|OpenBSD-x86_64) 
            log_warn "BSD detected, using Linux binaries (may not work)" >&2
            echo "linux${sep}amd64" ;;
        *BSD-aarch64|FreeBSD-aarch64|NetBSD-aarch64|OpenBSD-aarch64)
            log_warn "BSD detected, using Linux binaries (may not work)" >&2
            echo "linux${sep}arm64" ;;
        *) log_error "Unsupported platform: $os-$arch"; exit 1 ;;
    esac
}

download_extract() {
    local url="$1" dest="$2" strip="${3:-0}" temp tar_file
    # Check for curl availability
    command -v curl >/dev/null 2>&1 || { log_error "curl is required but not installed"; return 1; }
    
    temp=$(mktemp -d) || { log_error "Failed to create temporary directory"; return 1; }
    tar_file="$temp/archive.tar.gz"
    
    # Download and extract with strip-components
    if curl -L "$url" -o "$tar_file"; then
        # Both GNU tar and modern BSD tar support --strip-components
        # Use it directly instead of trying to detect support
        tar -xzf "$tar_file" -C "$dest" --strip-components="$strip" || {
            # Fallback: extract to temp dir and move files if strip-components fails
            local extract_temp="$temp/extract"
            mkdir -p "$extract_temp"
            tar -xzf "$tar_file" -C "$extract_temp"
            
            local source_dir="$extract_temp"
            if [[ "$strip" -gt 0 ]]; then
                # Strip one level (strip=1)
                source_dir="$extract_temp"/*/ 
                source_dir=$(echo $source_dir | head -n1)
                [[ -d "$source_dir" ]] || { log_error "Cannot strip directory level"; return 1; }
            fi
            mv "$source_dir"/* "$dest/" 2>/dev/null || cp -r "$source_dir"/* "$dest/"
        }
    else
        rm -rf "$temp"; log_error "Failed to download from $url"; return 1
    fi
    rm -rf "$temp"
}

setup_rustup() {
    command -v rustup >/dev/null 2>&1 && { log_success "rustup already installed"; return; }
    log_step "Installing rustup..."
    log_info "Lyquor tools require rustup for Rust toolchain management"
    ask_user "Install rustup now?" || { log_error "rustup required for Lyquor development"; exit 1; }
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-toolchain stable --profile minimal --no-modify-path -y
    export PATH="$HOME/.cargo/bin:$PATH"
    log_success "rustup installed"
}

setup_nightly_wasm() {
    command -v rustup >/dev/null 2>&1 || { log_error "rustup required"; exit 1; }
    
    local needs_setup=false
    
    # Check nightly toolchain
    if ! rustup toolchain list | grep -q "nightly"; then
        log_step "Installing nightly toolchain..."
        log_info "Lyquor requires wasm32 nightly toolchain to build Lyquids"
        ask_user "Install nightly toolchain?" || { log_error "nightly required for Lyquid development"; exit 1; }
        rustup toolchain install nightly
        needs_setup=true
    fi
    
    # Check rust-src component
    if ! rustup component list --toolchain nightly | grep -q "rust-src.*installed"; then
        log_step "Adding rust-src component..."
        rustup component add rust-src --toolchain nightly
        needs_setup=true
    fi
    
    # Check wasm32 target
    if ! rustup target list --toolchain nightly | grep -q "wasm32-unknown-unknown.*installed"; then
        log_step "Adding wasm32 target..."
        rustup target add wasm32-unknown-unknown --toolchain nightly
        needs_setup=true
    fi
    
    if $needs_setup; then
        log_success "nightly toolchain with wasm32 configured"
    else
        log_success "nightly toolchain with wasm32 ready"
    fi
}

setup_foundry() {
    local foundry_home="$HOME/.shakenup/foundry" bin_dir="$HOME/.shakenup/bin"
    [[ -f "$foundry_home/bin/forge" ]] && { log_success "Foundry already installed"; return; }
    
    log_step "Installing Foundry..."
    mkdir -p "$foundry_home/bin" "$bin_dir"
    local platform=$(detect_platform "foundry") url
    
    if [[ "$FOUNDRY_VERSION" == "stable" ]]; then
        local version=$(curl -s https://api.github.com/repos/foundry-rs/foundry/releases/latest | grep '"tag_name"' | sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')
        [[ -n "$version" ]] || { log_error "Failed to parse Foundry version"; exit 1; }
        url="https://github.com/foundry-rs/foundry/releases/download/$version/foundry_${version}_${platform}.tar.gz"
    else
        url="https://github.com/foundry-rs/foundry/releases/download/$FOUNDRY_VERSION/foundry_${FOUNDRY_VERSION}_${platform}.tar.gz"
    fi
    
    download_extract "$url" "$foundry_home/bin/" || exit 1
    chmod +x "$foundry_home/bin"/*
    for tool in forge cast anvil chisel; do
        [[ -f "$foundry_home/bin/$tool" ]] && ln -sf "../foundry/bin/$tool" "$bin_dir/$tool"
    done
    log_success "Foundry installed"
}

setup_lyquor() {
    local bin_dir="$HOME/.shakenup/bin" ldk_dir="$HOME/.shakenup/ldk" tools=(lyquor ladle setup-devnet shaker)
    local all_exist=true; for tool in "${tools[@]}"; do [[ -f "$bin_dir/$tool" ]] || { all_exist=false; break; }; done
    local ldk_exists=false; [[ -d "$ldk_dir" && -n "$(ls -A "$ldk_dir" 2>/dev/null)" ]] && ldk_exists=true
    $all_exist && $ldk_exists && { log_success "Lyquor tools and LDK already installed"; return; }
    
    log_step "Installing Lyquor tools and LDK..."
    mkdir -p "$bin_dir" "$ldk_dir"
    local platform=$(detect_platform "lyquor")
    
    # Download tools if needed
    if ! $all_exist; then
        local filename=$(curl -s https://api.github.com/repos/lyquor-labs/ldk/releases/tags/latest | \
            grep "browser_download_url.*${platform}\.tar\.gz" | sed -E 's|.*/([^"/]+\.tar\.gz)".*|\1|')
        [[ -n "$filename" ]] || { log_error "No Lyquor tools for $platform"; exit 1; }
        download_extract "https://github.com/lyquor-labs/ldk/releases/download/latest/$filename" "$bin_dir" 1 || exit 1
        chmod +x "$bin_dir"/*
    fi
    
    # Download LDK if needed
    if ! $ldk_exists; then
        download_extract "https://github.com/lyquor-labs/ldk/releases/download/latest/ldk.tar.gz" "$ldk_dir" 1 || exit 1
    fi
    
    log_success "Lyquor tools and LDK installed"
}

create_devnet_script() {
    cat > "$HOME/.shakenup/bin/start-devnet" << 'EOF'
#!/usr/bin/env bash
set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
rm -rf lyquor_db && LYQUOR_LOG=${LYQUOR_LOG:-info} "$SCRIPT_DIR/lyquor" --network devnet &
pid=$!
trap 'echo "Received signal, stopping devnet node..."; kill -INT "$pid" 2>/dev/null; wait "$pid"; exit' INT TERM
sleep 1
"$SCRIPT_DIR/setup-devnet" -b "$SCRIPT_DIR/../ldk/bartender/Cargo.toml" > /dev/null
wait "$pid"
EOF

    chmod +x "$HOME/.shakenup/bin/start-devnet"
    log_success "Devnet script created"
}

create_status_script() {
    mkdir -p "$HOME/.shakenup"
    
    cat > "$HOME/.shakenup/status" << 'EOF'
#!/usr/bin/env bash
echo "Shakenup Development Environment Status"
echo "======================================"
command -v rustc >/dev/null && {
    echo "✓ Rust: $(rustc +nightly --version 2>/dev/null || rustc --version)"
    rustup target list --toolchain nightly 2>/dev/null | grep -q "wasm32.*installed" && echo "✓ WASM: available" || echo "✗ WASM: missing"
} || echo "✗ Rust: not installed"
[[ -f "$HOME/.shakenup/bin/forge" ]] && echo "✓ Foundry: $($HOME/.shakenup/bin/forge --version)" || echo "✗ Foundry: not installed"
[[ -f "$HOME/.shakenup/bin/lyquor" ]] && echo "✓ Lyquor: installed" || echo "✗ Lyquor: not installed"
EOF
    
    chmod +x "$HOME/.shakenup/status"
    log_success "Status script created"
}

setup_shell_config() {
    local bin_dir="$HOME/.shakenup/bin" marker="# Added by shakenup"
    [[ ":$PATH:" == *":$bin_dir:"* ]] && { log_info "Already in PATH"; return; }
    
    local shell=$(basename "$SHELL") config_file
    case "$shell" in
        bash) config_file="$HOME/.bashrc" ;;
        zsh) config_file="$HOME/.zshenv" ;;
        ash) config_file="$HOME/.profile" ;;
        fish) config_file="$HOME/.config/fish/config.fish"; mkdir -p "$(dirname "$config_file")" ;;
        *) log_warn "Unknown shell: $shell" >&2; return ;;
    esac
    
    touch "$config_file"
    grep -q "$marker" "$config_file" && { log_info "PATH already configured"; return; }
    
    if [[ "$shell" == "fish" ]]; then
        printf '\n%s\nfish_add_path "%s"\n' "$marker" "$bin_dir" >> "$config_file"
    else
        printf '\n%s\nexport PATH="%s:$PATH"\n' "$marker" "$bin_dir" >> "$config_file"
    fi
    log_success "Shell configured"
}

main() {
    echo -e "${BOLD}${BLUE}Shakenup - Lyquor Development Environment Setup${NC}"
    echo "==============================================="
    echo
    
    setup_rustup
    setup_nightly_wasm
    setup_foundry
    setup_lyquor
    create_devnet_script
    create_status_script
    setup_shell_config
    
    log_success "Self-contained installation to ~/.shakenup/ succeeded!"
    log_info "Restart your shell to use the tools"
    log_info "Start devnet: start-devnet"
    log_info "Check status: ~/.shakenup/status"
}

main "$@"
