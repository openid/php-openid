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

        $lib =& Net_OpenID_MathLibrary::getLibWrapper();

        // It's possible, but HIGHLY unlikely that a correct
        // implementation will fail by returning the same number twice

        $s = Net_OpenID_CryptUtil::getBytes(32);
        $t = Net_OpenID_CryptUtil::getBytes(32);
        $this->assertEquals(strlen($s), 32);
        $this->assertEquals(strlen($t), 32);
        $this->assertFalse($s == $t);

        $a = Net_OpenID_CryptUtil::randrange($lib->pow(2, 128));
        $b = Net_OpenID_CryptUtil::randrange($lib->pow(2, 128));

        // If $a is a float, it's because we're using fallback number
        // storage (PHP stores overflowed ints as floats).
        $this->assertFalse(is_float($a));
        $this->assertFalse(is_float($b));
        $this->assertFalse($b == $a);

        // Make sure that we can generate random numbers that are
        // larger than platform int size
        Net_OpenID_CryptUtil::randrange($lib->init(Net_OpenID_CryptUtil::maxint() + 1));
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

    function test_binaryLongConvert() {
        
        $lib =& Net_OpenID_MathLibrary::getLibWrapper();

        $MAX = Net_OpenID_CryptUtil::maxint();
        
        foreach (range(0, 499) as $iteration) {
            $n = $lib->init(0);
            foreach (range(0, 9) as $i) {
                $n = $lib->add($n, $lib->init(Net_OpenID_CryptUtil::randrange($MAX)));
            }

            $s = Net_OpenID_CryptUtil::longToBinary($n);
            $this->assertTrue(is_string($s));
            $n_prime = Net_OpenID_CryptUtil::binaryToLong($s);
            $this->assertEquals($lib->cmp($n, $n_prime), 0);
        }

        $cases = array(
                       array("\x00", 0),
                       array("\x01", 1),
                       array("\x00\xFF", 255),
                       array("\x00\x80", 128),
                       array("\x00\x81", 129),
                       array("\x00\x80\x00", 32768),
                       array("OpenID is cool", "1611215304203901150134421257416556")
                       );

        foreach ($cases as $case) {
            list($s, $n) = $case;
            $n_prime = Net_OpenID_CryptUtil::binaryToLong($s);
            $s_prime = Net_OpenID_CryptUtil::longToBinary($n);
            $this->assertEquals($lib->cmp($n, $n_prime), 0);
            $this->assertTrue($s == $s_prime);
        }
    }

    function test_longToBase64() {

        $lib =& Net_OpenID_MathLibrary::getLibWrapper();

        $lines = file_get_contents('Tests/n2b64', true);
        $this->assertTrue(is_string($lines));

        $lines = explode("\n", $lines);

        foreach ($lines as $line) {
            if (!$line) {
                continue;
            }
            $parts = explode(' ', $line);
            $this->assertEquals($parts[0],
                                Net_OpenID_CryptUtil::longToBase64($lib->init($parts[1])));
        }
    }

    function test_base64ToLong() {

        $lib =& Net_OpenID_MathLibrary::getLibWrapper();

        $lines = file_get_contents('Tests/n2b64', true);
        $this->assertTrue(is_string($lines));

        $lines = explode("\n", $lines);

        foreach ($lines as $line) {
            if (!$line) {
                continue;
            }
            $parts = explode(' ', $line);
            $this->assertEquals($lib->init($parts[1]),
                                Net_OpenID_CryptUtil::base64ToLong($parts[0]));
        }
    }
}

?>