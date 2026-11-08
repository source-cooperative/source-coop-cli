#!/bin/sh
# Installs (or updates) source-coop-staging: the CLI built for source.coop's
# staging environment by the "Staging build" workflow. It sits beside a
# production source-coop, and keeps its own login.
#
#   curl -LsSf https://github.com/source-cooperative/source-coop-cli/releases/download/staging/install.sh | sh
#
# SOURCE_COOP_STAGING_DIR  where to install it (default: ~/.local/bin)
# SOURCE_COOP_STAGING_URL  where the builds are (default: the staging pre-release)
set -eu

dir="${SOURCE_COOP_STAGING_DIR:-$HOME/.local/bin}"
url="${SOURCE_COOP_STAGING_URL:-https://github.com/source-cooperative/source-coop-cli/releases/download/staging}"

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) target=aarch64-apple-darwin ;;
  Darwin-x86_64) target=x86_64-apple-darwin ;;
  Linux-x86_64) target=x86_64-unknown-linux-gnu ;;
  Linux-aarch64 | Linux-arm64) target=aarch64-unknown-linux-gnu ;;
  *) echo "No staging build for $(uname -s) $(uname -m). Build it instead: cargo install --git https://github.com/source-cooperative/source-coop-cli --features staging" >&2; exit 1 ;;
esac

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
echo "Downloading source-coop-staging for $target" >&2
curl -fsSL "$url/source-coop-staging-$target.tar.gz" | tar -xz -C "$tmp"
mkdir -p "$dir"
mv "$tmp/source-coop-staging" "$dir/source-coop-staging"
chmod 755 "$dir/source-coop-staging"
echo "Installed $("$dir/source-coop-staging" --version) as $dir/source-coop-staging" >&2

case ":$PATH:" in
  *":$dir:"*) ;;
  *) echo "$dir isn't on your PATH: add it, or run $dir/source-coop-staging" >&2 ;;
esac
