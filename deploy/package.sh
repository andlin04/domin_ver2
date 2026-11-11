#!/bin/bash
# Build the install package from a clean checkout: dist/domin-VERSION-COMMIT.tar.gz plus its .sha256.
#   bash deploy/package.sh [REF]      REF defaults to HEAD; refuses a dirty tree for HEAD (the package = a commit)
# On the target (Debian 13 / Ubuntu 24.04, as root):
#   sha256sum -c domin-*.tar.gz.sha256 && tar -xzf domin-*.tar.gz && bash domin-*/deploy/install.sh --internal ...
set -euo pipefail
cd "$(dirname "$0")/.."
REF=${1:-HEAD}
if [ "$REF" = HEAD ] && [ -n "$(git status --porcelain --untracked-files=no)" ]; then
  echo "package.sh: uncommitted changes; commit first or pass a ref" >&2
  exit 1
fi
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' pyproject.toml | head -n1)
COMMIT=$(git rev-parse --short "$REF")
NAME=domin-$VERSION-$COMMIT
mkdir -p dist
# only what a host runs or an admin reads: no tests, no git files
git archive --format=tar.gz --prefix="$NAME/" -o "dist/$NAME.tar.gz" "$REF" \
  domin deploy pyproject.toml README.md SECURITY.md CHANGES.md
(cd dist && sha256sum "$NAME.tar.gz" > "$NAME.tar.gz.sha256")
echo "dist/$NAME.tar.gz ($(du -h "dist/$NAME.tar.gz" | cut -f1)), sha256 $(cut -c1-16 "dist/$NAME.tar.gz.sha256")..."
