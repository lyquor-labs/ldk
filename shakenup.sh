#!/usr/bin/env bash
set -euo pipefail

# Shakenup - Lyquor development environment setup
FOUNDRY_VERSION="stable"
SHAKENUP_DIR="${SHAKENUP_DIR:-$HOME/.shakenup}"

# Colors and logging
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
# Logo color: try RGB (#3a12ff), fallback to bright blue
LOGO_COLOR='\033[38;2;58;18;255m'
[[ "${COLORTERM:-}" != "truecolor" && "${COLORTERM:-}" != "24bit" ]] && LOGO_COLOR='\033[0;94m'
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${BOLD}${BLUE}==>${NC}${BOLD} $1${NC}"; }

ask_user() {
    local prompt="$1" default="${2:-yes}" response default_char
    default_char=$([[ "$default" == "yes" ]] && echo "y" || echo "n")
    read -p "$prompt $([[ "$default" == "yes" ]] && echo "[Y/n]" || echo "[y/N]"): " response < /dev/tty
    response="${response:-$default_char}"
    [[ "$response" =~ ^[yY] ]]
}

require_cc() {
    log_error "C compiler required for building Rust projects"
    exit 1
}

all_tools_exist() {
    local bin_dir="$1"; shift
    local tool
    for tool in "$@"; do
        [[ -f "$bin_dir/$tool" ]] || return 1
    done
    return 0
}

install_with_sudo() {
    local cmd="$1"
    echo "Running: $cmd"
    eval "$cmd"
}

handle_bsd_platform() {
    local sep="$1" arch="$2"
    log_warn "BSD detected, using Linux binaries (may not work)" >&2
    echo "linux${sep}${arch}"
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
            handle_bsd_platform "$sep" "amd64" ;;
        *BSD-aarch64|FreeBSD-aarch64|NetBSD-aarch64|OpenBSD-aarch64)
            handle_bsd_platform "$sep" "arm64" ;;
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
    if curl -L --connect-timeout 30 --max-time 300 "$url" -o "$tar_file"; then
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
                source_dir=$(echo "$source_dir" | head -n1)
                [[ -d "$source_dir" ]] || { log_error "Cannot strip directory level"; return 1; }
            fi
            mv "$source_dir"/* "$dest/" 2>/dev/null || cp -r "$source_dir"/* "$dest/"
        }
    else
        rm -rf "$temp"; log_error "Failed to download from $url"; return 1
    fi
    rm -rf "$temp"
}

check_cc() {
    command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1 || command -v clang >/dev/null 2>&1
}

install_build_tools() {
    check_cc && { log_success "C compiler already available"; return; }

    log_warn "C compiler not found - required for building Rust projects"
    local os=$(uname -s) sudo_cmd=""
    [[ $EUID -ne 0 ]] && sudo_cmd="sudo "

    case "$os" in
        Darwin)
            log_info "Xcode Command Line Tools provide the C compiler needed for building Rust projects"
            ask_user "Install Xcode Command Line Tools now?" || require_cc
            if ! xcode-select -p >/dev/null 2>&1; then
                xcode-select --install
                log_info "Complete the installation dialog and re-run this script"
                exit 0
            fi
            ;;
        Linux)
            [[ -f /etc/os-release ]] || {
                log_error "Cannot detect Linux distribution"
                log_info "Please install build-essential or equivalent C compiler package"
                exit 1
            }
            . /etc/os-release
            
            local package cmd description
            case "$ID" in
                ubuntu|debian)
                    package="build-essential"
                    description="package provides C compiler needed for building Rust projects"
                    cmd="${sudo_cmd}apt update && ${sudo_cmd}apt install -y build-essential"
                    ;;
                arch|manjaro)
                    package="base-devel"
                    description="group provides C compiler needed for building Rust projects"
                    cmd="${sudo_cmd}pacman -S --needed base-devel"
                    ;;
                fedora|rhel|centos)
                    package="Development Tools"
                    description="group provides C compiler needed for building Rust projects"
                    cmd="${sudo_cmd}dnf groupinstall -y \"Development Tools\""
                    ;;
                alpine)
                    package="build-base"
                    description="package provides C compiler needed for building Rust projects"
                    cmd="${sudo_cmd}apk add build-base"
                    ;;
                *)
                    log_error "Unsupported Linux distribution: $PRETTY_NAME"
                    log_info "Please install a C compiler manually and re-run this script"
                    exit 1
                    ;;
            esac
            
            log_info "$package $description"
            ask_user "Install $package now?$([[ -n "$sudo_cmd" ]] && echo " (requires sudo)")" || require_cc
            install_with_sudo "$cmd"
            ;;
        *)
            log_error "Unsupported operating system: $os"
            log_info "Please install a C compiler and re-run this script"
            exit 1
            ;;
    esac

    check_cc && log_success "C compiler installed successfully" || {
        log_error "C compiler installation failed"
        exit 1
    }
}

setup_rustup() {
    command -v rustup >/dev/null 2>&1 && { log_success "rustup already installed"; return; }
    log_step "Installing rustup..."
    log_info "Lyquor tools require rustup for Rust toolchain management"
    ask_user "Install rustup now?" || { log_error "rustup required for Lyquor development"; exit 1; }
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-toolchain stable --profile minimal --no-modify-path -y
    export PATH="$HOME/.cargo/bin:$PATH"

    # Create symlinks for rustup and cargo in shakenup bin directory
    local bin_dir="$SHAKENUP_DIR/bin"
    mkdir -p "$bin_dir"
    [[ -f "$HOME/.cargo/bin/rustup" ]] && ln -sf "$HOME/.cargo/bin/rustup" "$bin_dir/rustup"
    [[ -f "$HOME/.cargo/bin/cargo" ]] && ln -sf "$HOME/.cargo/bin/cargo" "$bin_dir/cargo"

    log_success "rustup installed"
    log_info "Consider adding ~/.cargo/bin to your PATH for direct access to Rust tools"
}

setup_nightly_wasm() {
    command -v rustup >/dev/null 2>&1 || { log_error "rustup required"; exit 1; }

    local needs_setup=false

    # Check nightly toolchain
    if ! rustup toolchain list | grep -q "nightly"; then
        log_info "Lyquor requires wasm32 nightly toolchain to build Lyquids"
        ask_user "Install nightly toolchain?" || { log_error "nightly required for Lyquid development"; exit 1; }
        log_step "Installing nightly toolchain..."
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
    local foundry_home="$SHAKENUP_DIR/foundry" bin_dir="$SHAKENUP_DIR/bin"
    [[ -f "$foundry_home/bin/forge" ]] && { log_success "Foundry already installed"; return; }

    log_step "Installing Foundry..."
    mkdir -p "$foundry_home/bin" "$bin_dir"
    local platform=$(detect_platform "foundry") url

    if [[ "$FOUNDRY_VERSION" == "stable" ]]; then
        local version=$(curl -s --connect-timeout 30 --max-time 60 https://api.github.com/repos/foundry-rs/foundry/releases/latest | grep '"tag_name"' | sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')
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

needs_lyquor_update() {
    local bin_dir="$1" ldk_dir="$2" version_file="$3" latest_filename="$4"
    local tools=(lyquor ladle setup-devnet shaker)
    
    # Check if tools and LDK exist
    if ! all_tools_exist "$bin_dir" "${tools[@]}" || ! [[ -d "$ldk_dir" && -n "$(ls -A "$ldk_dir" 2>/dev/null)" ]]; then
        return 0  # Need update
    fi
    
    # Check version
    if [[ -f "$version_file" ]]; then
        local current_version=$(cat "$version_file")
        if [[ "$current_version" != "$latest_filename" ]]; then
            log_info "New Lyquor version available: $latest_filename (current: $current_version)"
            ask_user "Update Lyquor tools?"
            return $?
        fi
    fi
    
    return 1  # No update needed
}

setup_lyquor() {
    local bin_dir="$SHAKENUP_DIR/bin" ldk_dir="$SHAKENUP_DIR/ldk"
    local version_file="$SHAKENUP_DIR/.lyquor_version"
    local platform=$(detect_platform "lyquor")

    # Get latest version info
    local latest_filename=$(curl -s --connect-timeout 30 --max-time 60 https://api.github.com/repos/lyquor-labs/ldk/releases/tags/latest | \
        grep "browser_download_url.*${platform}\.tar\.gz" | sed -E 's|.*/([^"/]+\.tar\.gz)".*|\1|')
    [[ -n "$latest_filename" ]] || { log_error "No Lyquor tools for $platform"; exit 1; }

    if ! needs_lyquor_update "$bin_dir" "$ldk_dir" "$version_file" "$latest_filename"; then
        log_success "Lyquor tools and LDK already up to date"
        return
    fi

    log_step "Installing Lyquor tools and LDK..."
    mkdir -p "$bin_dir" "$ldk_dir"

    # Download and install tools
    download_extract "https://github.com/lyquor-labs/ldk/releases/download/latest/$latest_filename" "$bin_dir" 1 || exit 1
    chmod +x "$bin_dir"/*

    # Download and install LDK
    download_extract "https://github.com/lyquor-labs/ldk/releases/download/latest/ldk.tar.gz" "$ldk_dir" 1 || exit 1

    # Save version info
    echo "$latest_filename" > "$version_file"
    log_success "Lyquor tools and LDK installed ($latest_filename)"
}

create_devnet_script() {
    cat > "$SHAKENUP_DIR/bin/start-devnet" << 'EOF'
#!/usr/bin/env bash
set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
rm -rf lyquor_db && LYQUOR_LOG=${LYQUOR_LOG:-info} "$SCRIPT_DIR/lyquor" --network devnet &
pid=$!
trap 'echo "Received signal, stopping devnet node..."; kill -INT "$pid" 2>/dev/null; wait "$pid"; exit' INT TERM
sleep 1
if ! "$SCRIPT_DIR/setup-devnet" -b "$SCRIPT_DIR/../ldk/bartender/Cargo.toml" > /dev/null; then
    kill -INT "$pid" 2>/dev/null; wait "$pid"; exit 1
fi
wait "$pid"
EOF

    chmod +x "$SHAKENUP_DIR/bin/start-devnet"
    log_success "Devnet script created"
}

create_status_script() {
    cat > "$SHAKENUP_DIR/status" << EOF
#!/usr/bin/env bash
SHAKENUP_DIR="\${SHAKENUP_DIR:-\$HOME/.shakenup}"
echo "Shakenup Development Environment Status"
echo "======================================"
command -v rustc >/dev/null && {
    echo "✓ Rust: \$(rustc +nightly --version 2>/dev/null || rustc --version)"
    if rustup target list --toolchain nightly 2>/dev/null | grep -q "wasm32.*installed" && \\
       rustup component list --toolchain nightly 2>/dev/null | grep -q "rust-src.*installed"; then
        echo "✓ WASM: available (wasm32 + rust-src)"
    else
        echo "✗ WASM: missing (need both wasm32 target and rust-src component for nightly)"
    fi
} || echo "✗ Rust: not installed"
[[ -f "\$SHAKENUP_DIR/bin/forge" ]] && echo "✓ Foundry: \$(\$SHAKENUP_DIR/bin/forge --version)" || echo "✗ Foundry: not installed"
[[ -f "\$SHAKENUP_DIR/bin/lyquor" ]] && echo "✓ Lyquor: installed" || echo "✗ Lyquor: not installed"
EOF

    chmod +x "$SHAKENUP_DIR/status"
    log_success "Status script created"
}

setup_shell_config() {
    local bin_dir="$SHAKENUP_DIR/bin" marker="# Added by shakenup"
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

install_script() {
    local bin_dir="$SHAKENUP_DIR/bin"
    local ldk_dir="$SHAKENUP_DIR/ldk"
    local script_path="$bin_dir/shakenup"
    local ldk_script="$ldk_dir/shakenup.sh"

    if [[ -f "$ldk_script" ]]; then
        log_step "Installing shakenup script..."
        cp "$ldk_script" "$script_path"
        chmod +x "$script_path"
        log_success "Shakenup script installed to $script_path"
    else
        log_warn "Shakenup script not found in LDK"
    fi
}

main() {
    echo -e "${BOLD}${LOGO_COLOR}"
    cat << 'EOF'
  [ ]    ____  _           _
 /   \  / ___|| |__   __ _| | _____ _ __  _   _ _ _
[=====] \___ \| '_ \ / _` | |/ / _ \ '_ \| | | | '_ \
|     |  ___) | | | | (_| |   <  __/ | | | |_| | |_) |
 \___/  |____/|_| |_|\__,_|_|\_\___|_| |_|\__,_| .__/
                                               |_|
EOF
    echo -e "${NC}"
    echo -e "${BOLD}${BLUE}Lyquor Development Environment Setup${NC}"
    echo

    setup_shell_config
    # Add shakenup bin to PATH for current session
    export PATH="$SHAKENUP_DIR/bin:$PATH"

    install_build_tools
    setup_rustup
    setup_nightly_wasm
    setup_foundry
    setup_lyquor
    install_script
    create_devnet_script
    create_status_script

    log_success "Installation to $SHAKENUP_DIR succeeded!"
    log_info "Source the shell config or restart your shell to use the tools."
    log_info "Run 'shakenup' to update your environment in the future."
    log_info "Start devnet: start-devnet"
    log_info "Check tools' status: $SHAKENUP_DIR/status"
}

main "$@"
