<?php

require_once('Net/OpenID/CryptUtil.php');

$lib =& Net_OpenID_MathLibrary::getLibWrapper();

print "Using library type " . $lib->type . "\n";

?>
