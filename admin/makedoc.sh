#!/bin/sh
set -v
phpdoc -p -t doc -d Auth,tutorials -ti "JanRain OpenID Library" \
    --ignore \*~,BigMath.php,CryptUtil.php,DiffieHellman.php,HMACSHA1.php,KVForm.php,Parse.php,TrustRoot.php \
    -dn "OpenID" -o "HTML:frames:phphtmllib"
