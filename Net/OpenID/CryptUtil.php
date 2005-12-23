<?php

class Net_OpenID_CryptUtil {
	function getBytes($num_bytes) {
		$f = fopen("/dev/urandom", "r");
		$bytes = fread($f, $num_bytes);
		fclose($f);
		return $bytes;
	}
}
