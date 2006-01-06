<?php

/**
 * Tests for the CryptUtil functions.
 *
 * PHP versions 4 and 5
 *
 * LICENSE: See the COPYING file included in this distribution.
 *
 * @package OpenID
 * @author JanRain, Inc. <openid@janrain.com>
 * @copyright 2005 Janrain, Inc.
 * @license http://www.gnu.org/copyleft/lesser.html LGPL
 */

require_once('PHPUnit.php');
require_once('Net/OpenID/CryptUtil.php');

class Tests_Net_OpenID_ByteOps extends PHPUnit_TestCase {
    function test_length()
    {
        $cases = array(1, 10, 255);
        foreach ($cases as $length) {
            $data = Net_OpenID_CryptUtil::getBytes($length);
            $this->assertEquals(strlen($data), $length);
        }
    }

    function test_different()
    {
        $num_iterations = 100;
        $data_length = 20;

        $data = Net_OpenID_CryptUtil::getBytes($num_iterations);
        for ($i = 0; $i < $num_iterations; $i++) {
            $last = $data;
            $data = Net_OpenID_CryptUtil::getBytes($num_iterations);
            $this->assertFalse($data == $last);
        }
    }

    function test_cryptrand()
    {
        // It's possible, but HIGHLY unlikely that a correct
        // implementation will fail by returning the same number twice

        $s = Net_OpenID_CryptUtil::getBytes(32);
        $t = Net_OpenID_CryptUtil::getBytes(32);
        $this->assertEquals(strlen($s), 32);
        $this->assertEquals(strlen($t), 32);
        $this->assertFalse($s == $t);
    }

    function test_strxor()
    {
        $NUL = "\x00";

        $cases = array(
                       array($NUL, $NUL, $NUL),
                       array("\x01", $NUL, "\x01"),
                       array("a", "a", $NUL),
                       array("a", $NUL, "a"),
                       array("abc", str_repeat($NUL, 3), "abc"),
                       array(str_repeat("x", 10),
                             str_repeat($NUL, 10),
                             str_repeat("x", 10)),
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
                           array(str_repeat($NUL, 3),
                                 str_repeat($NUL, 4)),
                           array(implode('', array_map('chr',
                                                       range(0, 255))),
                                 implode('', array_map('chr',
                                                       range(0, 127))))
                           );

        while(list($index, $values) = each($exc_cases)) {
            list($aa, $bb) = $values;
            $unexpected = Net_OpenID_CryptUtil::strxor($aa, $bb);
            $this->assertNull($unexpected);
        }
    }

    function test_reversed()
    {
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

class Tests_Net_OpenID_BinLongConvertRnd extends PHPUnit_TestCase {
    var $lib;
    var $max;

    function Tests_Net_OpenID_BinLongConvertRnd(&$lib, $max)
    {
        $this->lib =& $lib;
        $this->max = $max;
    }

    function runTest()
    {
        $n = $this->lib->init(0);
        foreach (range(0, 9) as $i) {
            $rnd = Net_OpenID_CryptUtil::randrange($this->max);
            $n = $this->lib->add($n, $rnd);
        }
        $s = Net_OpenID_CryptUtil::longToBinary($n);
        $this->assertTrue(is_string($s));
        $n_prime = Net_OpenID_CryptUtil::binaryToLong($s);
        $this->assertEquals($this->lib->cmp($n, $n_prime), 0);
    }
}

class Tests_Net_OpenID_BinLongConvert extends PHPUnit_TestCase {
    var $lib;
    var $bin;
    var $lng;

    function Tests_Net_OpenID_BinLongConvert(&$lib, $bin, $lng)
    {
        $this->lib =& $lib;
        $this->bin = $bin;
        $this->lng = $lng;
    }

    function runTest()
    {
        $n_prime = Net_OpenID_CryptUtil::binaryToLong($this->bin);
        $s_prime = Net_OpenID_CryptUtil::longToBinary($this->lng);
        $this->assertEquals($this->lib->cmp($this->lng, $n_prime), 0);
        $this->assertTrue($this->bin == $s_prime);
    }
}

class Tests_Net_OpenID_Base64ToLong extends PHPUnit_TestCase {
    var $num;
    var $b64;
    var $lib;

    function Tests_Net_OpenID_Base64ToLong(&$lib, $b64, $num)
    {
        $this->lib = $lib;
        $this->b64 = $b64;
        $this->num = $num;
    }

    function runTest()
    {
        $actual = Net_OpenID_CryptUtil::base64ToLong($this->b64);
        $this->assertTrue($this->lib->cmp($this->num, $actual) == 0);
    }
}

class Tests_Net_OpenID_LongToBase64 extends Tests_Net_OpenID_Base64ToLong {
    function Tests_Net_OpenID_LongToBase64(&$lib, $b64, $num)
    {
        $this->lib = $lib;
        $this->b64 = $b64;
        $this->num = $num;
    }

    function runTest()
    {
        $actual = Net_OpenID_CryptUtil::longToBase64($this->num);
        $this->assertEquals($this->b64, $actual);
    }
}

class Tests_Net_OpenID_RandRange extends PHPUnit_TestCase {
    function Tests_Net_OpenID_RandRange(&$lib)
    {
        $this->lib =& $lib;
    }

    function runTest()
    {
        $stop = $this->lib->pow(2, 128);
        $a = Net_OpenID_CryptUtil::randrange($stop);
        $b = Net_OpenID_CryptUtil::randrange($stop);

        $this->assertFalse($this->lib->cmp($b, $a) == 0, "Same: $a $b");

        $n = $this->lib->init(Net_OpenID_CryptUtil::maxint());
        $n = $this->lib->add($n, 1);

        // Make sure that we can generate random numbers that are
        // larger than platform int size
        $result = Net_OpenID_CryptUtil::randrange($n);

        // What can we say about the result?
    }
}

class Tests_Net_OpenID_CryptUtil extends PHPUnit_TestSuite {
    function _parseBase64Data()
    {
        $lines = file_get_contents('Tests/n2b64', true);
        $lines = explode("\n", $lines);

        $data = array();
        foreach ($lines as $line) {
            if (!$line) {
                continue;
            }
            list($b64, $ascii) = explode(' ', $line);
            $data[$b64] = $ascii;
        }
        return $data;
    }

    function Tests_Net_OpenID_CryptUtil($name)
    {
        $this->setName($name);
        
        if (!defined('Net_OpenID_NO_MATH_SUPPORT')) {
            $this->addTestSuite('Tests_Net_OpenID_BigInt');

            $lib =& Net_OpenID_MathLibrary::getLibWrapper();
            $max = Net_OpenID_CryptUtil::maxint();
            $upper = defined('Tests_Net_OpenID_thorough') ? 499 : 3;

            foreach (range(0, $upper) as $iteration) {
                $test = new Tests_Net_OpenID_BinLongConvertRnd($lib, $max);
                $test->setName("BinLongConvertRnd " . strval($iteration));
                $this->addTest($test);
            }

            $cases = array(
                "\x00" => 0,
                "\x01" => 1,
                "\x00\xFF" => 255,
                "\x00\x80" => 128,
                "\x00\x81" => 129,
                "\x00\x80\x00" => 32768,
                "OpenID is cool" => "1611215304203901150134421257416556"
                );

            foreach ($cases as $bin => $lng_m) {
                $lng = $lib->init($lng_m);
                $test = new Tests_Net_OpenID_BinLongConvert($lib, $bin, $lng);
                $test->setName('BinLongConvert ' . bin2hex($bin));
                $this->addTest($test);
            }

            $count = defined('Tests_Net_OpenID_thorough') ? -1 : 2;
            $data = $this->_parseBase64Data();
            foreach ($data as $b64 => $num_s) {
                // Only test the first few unless thorough is defined
                if (strlen($num_s) > 5) {
                    if ($count == 0) {
                        break;
                    } else {
                        $count -= 1;
                    }
                }
                $num = $lib->init($num_s);
                $test = new Tests_Net_OpenID_Base64ToLong($lib, $b64, $num);
                $test->setName("B64->Long $num_s");
                $this->addTest($test);

                $test = new Tests_Net_OpenID_LongToBase64($lib, $b64, $num);
                $test->setName("Long->B64 $num_s");
                $this->addTest($test);
            }

            $test = new Tests_Net_OpenID_RandRange($lib);
            $test->setName('Big number randrange');
            $this->addTest($test);
        }

        $this->addTestSuite('Tests_Net_OpenID_ByteOps');
    }
}

?>