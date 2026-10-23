#!/bin/sh
# Switch the running Apache module between the two builds made by build_php.sh.
set -eu
case "${1:-}" in
  clean)       SRC=/tmp/libphp-clean.so ;;
  instrumented) SRC=/tmp/libphp-instrumented.so ;;
  *) echo "usage: $0 clean|instrumented"; exit 2 ;;
esac
[ -f "$SRC" ] || { echo "missing $SRC (run build_php.sh first)"; exit 1; }
sudo cp "$SRC" /usr/lib/apache2/modules/libphp.so
sudo systemctl restart apache2
echo "using $1 module; trace strings: $(strings /usr/lib/apache2/modules/libphp.so | grep -c 'INIT FRESH')"
