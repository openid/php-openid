<?php

require_once('PHPUnit.php');
require_once('Net/OpenID/CryptUtil.php');

class Tests_Net_OpenID_CryptUtil extends PHPUnit_TestCase {
    function test_length() {
        $cases = array(1, 10, 255);
        foreach ($cases as $length) {
            $data = Net_OpenID_CryptUtil::getBytes($length);
            $this->assertEquals(strlen($data), $length);
        }
    }

    function test_different() {
        $num_iterations = 100;
        $data_length = 20;

        $data = Net_OpenID_CryptUtil::getBytes($num_iterations);
        for ($i = 0; $i < $num_iterations; $i++) {
            $last = $data;
            $data = Net_OpenID_CryptUtil::getBytes($num_iterations);
            $this->assertFalse($data == $last);
        }
    }
}

?>