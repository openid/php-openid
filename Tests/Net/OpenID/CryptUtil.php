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

    function test_cryptrand() {
        return;
        // It's possible, but HIGHLY unlikely that a correct
        // implementation will fail by returning the same number twice

        $s = Net_OpenID_CryptUtil::getBytes(32);
        $t = Net_OpenID_CryptUtil::getBytes(32);
        $this->assertEquals(strlen($s), 32);
        $this->assertEquals(strlen($t), 32);
        $this->assertFalse($s == $t);

        $a = Net_OpenID_CryptUtil::randrange(pow(2, 128));
        $b = Net_OpenID_CryptUtil::randrange(pow(2, 128));
        // assert(is_long($a));
        // assert(is_long($b));
        // assert($b != $a);

        // Make sure that we can generate random numbers that are
        // larger than platform int size
        // Net_OpenID_CryptUtil::randrange(INT_MAX + 1);
    }

    function test_strxor() {
        $NUL = "\x00";

        $cases = array(
                       array($NUL, $NUL, $NUL),
                       array("\x01", $NUL, "\x01"),
                       array("a", "a", $NUL),
                       array("a", $NUL, "a"),
                       array("abc", str_repeat($NUL, 3), "abc"),
                       array(str_repeat("x", 10), str_repeat($NUL, 10), str_repeat("x", 10)),
                       array("\x01", "\x02", "\x03"),
                       array("\xf0", "\x0f", "\xff"),
                       array("\xff", "\x0f", "\xf0"),
                       );

        while (list($index, $values) = each($cases)) {
            list($aa, $bb, $expected) = $values;
            $actual = Net_OpenID_CryptUtil::strxor($aa, $bb);
            $this->assertEquals($actual, $expected);
        }

        $exc_cases = array(
                           array('', 'a'),
                           array('foo', 'ba'),
                           array(str_repeat($NUL, 3), str_repeat($NUL, 4)),
                           array(implode('', array_map('chr', range(0, 255))),
                                 implode('', array_map('chr', range(0, 127))))
                           );

        while(list($index, $values) = each($exc_cases)) {
            list($aa, $bb) = $values;
            $unexpected = Net_OpenID_CryptUtil::strxor($aa, $bb);
            $this->assertNull($unexpected);
        }
    }

    function test_reversed() {
        $cases = array(
                       array('', ''),
                       array('a', 'a'),
                       array('ab', 'ba'),
                       array('abc', 'cba'),
                       array('abcdefg', 'gfedcba'),
                       array(array(), array()),
                       array(array(1), array(1)),
                       array(array(1,2), array(2,1)),
                       array(array(1,2,3), array(3,2,1)),
                       array(range(0, 999), array_reverse(range(0, 999)))
                       );

        while (list($index, $values) = each($cases)) {
            list($case, $expected) = $values;
            $actual = Net_OpenID_CryptUtil::reversed($case);
            $this->assertEquals($actual, $expected);
            $twice = Net_OpenID_CryptUtil::reversed($actual);
            $this->assertEquals($twice, $case);
        }
    }
}

?>