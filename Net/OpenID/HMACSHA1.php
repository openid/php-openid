<?php

define('SHA1_BLOCKSIZE', 64);

if (FALSE && function_exists('mhash')) {
    function Net_OpenID_HMACSHA1($key, $text) {
        return mhash(MHASH_SHA1, $text, $key);
    }

} else {
    if (!function_exists('sha1')) {
		// XXX: include the SHA1 code from Dan Libby's OpenID library
		trigger_error('No SHA1 function found', E_USER_ERROR);
	} else {
		function sha1_raw($text) {
			$hex = sha1($text);
			$raw = '';
			for ($i = 0; $i < 40; $i += 2) {
				$hexcode = substr($hex, $i, 2);
				$charcode = (int)base_convert($hexcode, 16, 10);
				$raw .= chr($charcode);
			}
			return $raw;
		}
	}

	function Net_OpenID_HMACSHA1($key, $text) {
		if (strlen($key) > SHA1_BLOCKSIZE) {
			$key = sha1_raw($key, TRUE);
		}

		$key = str_pad($key, SHA1_BLOCKSIZE, chr(0x00));
		$ipad = str_repeat(chr(0x36), SHA1_BLOCKSIZE);
		$opad = str_repeat(chr(0x5c), SHA1_BLOCKSIZE);
		$hash1 = sha1_raw(($key ^ $ipad) . $text, TRUE);
		$hmac = sha1_raw(($key ^ $opad) . $hash1, TRUE);
		return $hmac;
 	}
}

?>