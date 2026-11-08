#!/bin/sh
# Installs (or updates) a preview of the CLI built by the "Preview build"
# workflow, as source-coop-NAME. It sits beside a production source-coop, and
# a staging build keeps its own login. Each preview's pre-release has a copy of
# this script with its name set:
#
#   curl -LsSf https://github.com/source-cooperative/source-coop-cli/releases/download/NAME/install.sh | sh
#
# SOURCE_COOP_PREVIEW_DIR  where to install it (default: ~/.local/bin)
# SOURCE_COOP_PREVIEW_URL  where the builds are (default: the preview's pre-release)
set -eu

# The preview: set by the workflow when it publishes this script.
name=staging

command="source-coop-$name"
dir="${SOURCE_COOP_PREVIEW_DIR:-$HOME/.local/bin}"
url="${SOURCE_COOP_PREVIEW_URL:-https://github.com/source-cooperative/source-coop-cli/releases/download/$name}"

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) target=aarch64-apple-darwin ;;
  Darwin-x86_64) target=x86_64-apple-darwin ;;
  Linux-x86_64) target=x86_64-unknown-linux-gnu ;;
  Linux-aarch64 | Linux-arm64) target=aarch64-unknown-linux-gnu ;;
  *) echo "No preview build for $(uname -s) $(uname -m). Build the branch instead, with cargo install --git https://github.com/source-cooperative/source-coop-cli" >&2; exit 1 ;;
esac

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
echo "Downloading $command for $target" >&2
# To a file first: piped, a failed download would reach tar as an empty
# archive, which macOS's tar accepts.
curl -fsSL -o "$tmp/build.tar.gz" "$url/$command-$target.tar.gz"
tar -xzf "$tmp/build.tar.gz" -C "$tmp"
chmod 755 "$tmp/$command"
mkdir -p "$dir"
# Into the folder, then renamed over the old one, so a copy running now is
# never written over in place.
mv "$tmp/$command" "$dir/.$command.new"
mv "$dir/.$command.new" "$dir/$command"
echo "Installed $("$dir/$command" --version) as $dir/$command" >&2

case ":$PATH:" in
  *":$dir:"*) ;;
  *) echo "$dir isn't on your PATH: add it, or run $dir/$command" >&2 ;;
esac
