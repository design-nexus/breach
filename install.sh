#!/bin/sh
# breach installer.
# One-liner:
#   curl -fsSL https://raw.githubusercontent.com/design-nexus/breach/main/install.sh | sh
set -eu

REPO="${NEXUS_MSF_REPO:-https://github.com/design-nexus/breach}"
BIN_NAME="breach"
NEED_RUST_MAJOR=1
NEED_RUST_MINOR=88

say() { printf '%s\n' "$*"; }
err() { printf 'error: %s\n' "$*" >&2; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

ensure_path_cargo() {
  if [ -f "$HOME/.cargo/env" ]; then
    # shellcheck disable=SC1091
    . "$HOME/.cargo/env"
  fi
  PATH="$HOME/.cargo/bin:$PATH"
  export PATH
}

rustc_ok() {
  have rustc || return 1
  ver=$(rustc -V 2>/dev/null | awk '{print $2}' | cut -d. -f1,2)
  major=${ver%%.*}
  minor=${ver#*.}
  minor=${minor%%.*}
  [ "${major:-0}" -gt "$NEED_RUST_MAJOR" ] && return 0
  [ "${major:-0}" -eq "$NEED_RUST_MAJOR" ] && [ "${minor:-0}" -ge "$NEED_RUST_MINOR" ]
}

run_root() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  elif have sudo; then
    sudo "$@"
  else
    return 1
  fi
}

cc_ok() {
  have cc || have gcc || have clang
}

hint_cc() {
  err "C compiler/linker (cc) not found. Install a toolchain, then re-run:
  Debian/Ubuntu:  sudo apt-get install -y build-essential pkg-config
  Fedora:         sudo dnf install -y gcc make pkg-config
  Arch:           sudo pacman -S --needed base-devel
  Alpine:         sudo apk add build-base pkgconf
  macOS:          xcode-select --install"
}

ensure_cc() {
  if cc_ok; then
    return 0
  fi
  say "C compiler (cc) not found — installing a linker/toolchain…"
  if have apt-get; then
    export DEBIAN_FRONTEND=noninteractive
    run_root apt-get update -y \
      && run_root apt-get install -y build-essential pkg-config git curl \
      || hint_cc
  elif have dnf; then
    run_root dnf install -y gcc make pkg-config git curl || hint_cc
  elif have yum; then
    run_root yum install -y gcc make pkg-config git curl || hint_cc
  elif have pacman; then
    run_root pacman -S --noconfirm --needed base-devel git curl || hint_cc
  elif have apk; then
    run_root apk add --no-cache build-base pkgconf git curl || hint_cc
  elif have zypper; then
    run_root zypper install -y gcc make pkg-config git curl || hint_cc
  elif have brew; then
    brew install pkg-config || true
  elif [ "$(uname -s)" = "Darwin" ]; then
    say "Install Apple Command Line Tools, then re-run:"
    say "  xcode-select --install"
    err "C compiler (cc) not found"
  else
    hint_cc
  fi
  cc_ok || hint_cc
}

ensure_git() {
  have git && return 0
  say "git not found — installing…"
  if have apt-get; then
    export DEBIAN_FRONTEND=noninteractive
    run_root apt-get update -y && run_root apt-get install -y git
  elif have dnf; then
    run_root dnf install -y git
  elif have yum; then
    run_root yum install -y git
  elif have pacman; then
    run_root pacman -S --noconfirm --needed git
  elif have apk; then
    run_root apk add --no-cache git
  elif have zypper; then
    run_root zypper install -y git
  elif have brew; then
    brew install git
  fi
  have git || err "git is required (install git, then re-run)"
}

ensure_build_deps() {
  ensure_cc
  ensure_git
  if rustc_ok && have cargo; then
    return 0
  fi
  say "Installing Rust toolchain (rustup)…"
  if ! have curl; then
    err "curl is required to install rustup"
  fi
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
  ensure_path_cargo
  rustc_ok || err "rustc $NEED_RUST_MAJOR.$NEED_RUST_MINOR+ is required (Ratatui 0.30.2)"
  have cargo || err "cargo not found after rustup install"
}

install_from_git() {
  say "Building breach from $REPO…"
  cargo install --git "$REPO" --locked --force "$BIN_NAME"
}

warn_msf() {
  if have msfrpcd || have msfconsole; then
    say "metasploit: $(command -v msfconsole 2>/dev/null || command -v msfrpcd)"
  else
    say ""
    say "note: Metasploit Framework is not on PATH."
    say "      breach --demo works without it; live RPC needs msfrpcd."
  fi
}

main() {
  ensure_path_cargo
  ensure_build_deps
  install_from_git
  warn_msf
  dest=$(command -v "$BIN_NAME" || true)
  say ""
  say "Installed: ${dest:-$HOME/.cargo/bin/$BIN_NAME}"
  say "Run:       $BIN_NAME --demo"
  say "Live:      NEXUS_MSF_RPC_PASS=… $BIN_NAME"
  say ""
  case ":$PATH:" in
    *":$HOME/.cargo/bin:"*) ;;
    *)
      say "Add cargo to PATH for this shell:"
      say "  . \"\$HOME/.cargo/env\""
      ;;
  esac
}

main
