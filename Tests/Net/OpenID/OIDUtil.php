<?php

require_once('PHPUnit.php');
require_once('Net/OpenID/OIDUtil.php');

class Tests_Net_OpenID_OIDUtil extends PHPUnit_TestCase {
    function test_base64() {

        // This is not good for international use, but PHP doesn't
        // appear to provide access to the local alphabet.
        $letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        $digits = "0123456789";
        $extra = "+/=";
        $allowed_s = $letters . $digits . $extra;
        $allowed_d = array();

        for ($i = 0; $i < strlen($allowed_s); $i++) {
            $c = $allowed_s[$i];
            $allowed_d[$c] = null;
        }

        function checkEncoded($obj, $str, $allowed_array) {
            for ($i = 0; $i < strlen($str); $i++) {
                $obj->assertTrue(array_key_exists($str[$i], $allowed_array));
            }
        }

        $cases = array(
                       "",
                       "x",
                       "\x00",
                       "\x01",
                       str_repeat("\x00", 100),
                       implode("", array_map('chr', range(0, 255)))
                       );

        foreach ($cases as $s) {
            $b64 = Net_OpenID_toBase64($s);
            checkEncoded($this, $b64, $allowed_d);
            $s_prime = Net_OpenID_fromBase64($b64);
            $this->assertEquals($s_prime, $s);
        }

        function random_ordinal($unused) {
            return rand(0, 255);
        }

        // Randomized test
        foreach (range(0, 49) as $i) {
            $n = rand(0, 2048);
            $s = implode("", array_map('chr', array_map('random_ordinal', range(0, $n))));
            $b64 = Net_OpenID_toBase64($s);
            checkEncoded($this, $b64, $allowed_d);
            $s_prime = Net_OpenID_fromBase64($b64);
            $this->assertEquals($s_prime, $s);
        }
    }
}

?>