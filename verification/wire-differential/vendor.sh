#!/usr/bin/env bash
# Builds vendor/quinn-proto from the registry package of quinn-proto 0.11.19.
#
# The frame, range_set and packet modules of quinn-proto are private. The copy
# changes visibility only, as vendor/quinn-proto.visibility.diff lists, so that
# the differential tests can call the frame iterator, the frame encoders and the
# packet number functions.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
version=0.11.19
checksum=0e750cca55fe4f0439a15d0bb529da9651e79993e8e72c61a899a36d462befbe
name="quinn-proto-$version.crate"
target="$here/vendor/quinn-proto"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cached=$(ls "${CARGO_HOME:-$HOME/.cargo}"/registry/cache/*/"$name" 2>/dev/null | head -1 || true)
if [[ -n "$cached" ]]; then
    cp "$cached" "$work/$name"
else
    curl --fail --silent --show-error --location \
        --output "$work/$name" "https://static.crates.io/crates/quinn-proto/$name"
fi
echo "$checksum  $work/$name" | sha256sum --check --quiet

tar --extract --gzip --file "$work/$name" --directory "$work"
rm -rf "$target"
mv "$work/quinn-proto-$version" "$target"
patch --quiet --strip=1 --directory="$target" < "$here/vendor/quinn-proto.visibility.diff"
