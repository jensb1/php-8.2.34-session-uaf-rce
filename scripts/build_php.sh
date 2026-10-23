#!/bin/sh
# Build PHP 8.2.34 twice: clean -O2 (no traces) and instrumented -g (with [ser]).
# Run from the repository root. Requires the deps listed in README.md.
set -eu
V=8.2.34
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$HOME"
[ -f "php-$V.tar.gz" ] || curl -fsSLO "https://www.php.net/distributions/php-$V.tar.gz"
rm -rf "php-$V" && tar xf "php-$V.tar.gz"
cd "php-$V"

echo "=== clean -O2 build ==="
./configure --prefix=/opt/php-clean --with-apxs2=/usr/bin/apxs2 --disable-all \
  --enable-session --enable-ctype --enable-tokenizer --enable-filter --enable-cli \
  CFLAGS="-O2" >/tmp/php-clean-conf.log 2>&1
make -j"$(nproc)" >/tmp/php-clean-make.log 2>&1
cp libs/libphp.so /tmp/libphp-clean.so
echo "clean module -> /tmp/libphp-clean.so"

echo "=== instrumented -g build ==="
make clean >/dev/null 2>&1 || true
cp "$ROOT/instrumentation/var.c" ext/standard/var.c
./configure --prefix=/opt/php-lab --with-apxs2=/usr/bin/apxs2 --disable-all \
  --enable-session --enable-ctype --enable-tokenizer --enable-filter --enable-cli \
  CFLAGS="-g -O2" >/tmp/php-lab-conf.log 2>&1
make -j"$(nproc)" >/tmp/php-lab-make.log 2>&1
cp libs/libphp.so /tmp/libphp-instrumented.so
sudo make install
echo "instrumented module installed: /usr/lib/apache2/modules/libphp.so"
