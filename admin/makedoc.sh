#!/bin/sh
set -v
phpdoc -p -t doc -d Auth -ti "JanRain OpenID Library" \
    --ignore \*~ \
    -dn "OpenID" -o "HTML:frames:phphtmllib"
