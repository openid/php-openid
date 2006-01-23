<?php

/**
 * Tests for the BigMath functions.
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
require_once('Auth/OpenID/BigMath.php');

class Tests_Auth_OpenID_BinLongConvertRnd extends PHPUnit_TestCase {
    var $lib;
    var $max;

    function Tests_Auth_OpenID_BinLongConvertRnd(&$lib, $max)
    {
        $this->lib =& $lib;
        $this->max = $max;
    }

    function runTest()
    {
        $n = $this->lib->init(0);
        foreach (range(0, 9) as $i) {
            $rnd = Auth_OpenID_randrange($this->max);
            $n = $this->lib->add($n, $rnd);
        }
        $s = Auth_OpenID_longToBinary($n);
        $this->assertTrue(is_string($s));
        $n_prime = Auth_OpenID_binaryToLong($s);
        $this->assertEquals($this->lib->cmp($n, $n_prime), 0);
    }
}

class Tests_Auth_OpenID_BinLongConvert extends PHPUnit_TestCase {
    var $lib;
    var $bin;
    var $lng;

    function Tests_Auth_OpenID_BinLongConvert(&$lib, $bin, $lng)
    {
        $this->lib =& $lib;
        $this->bin = $bin;
        $this->lng = $lng;
    }

    function runTest()
    {
        $n_prime = Auth_OpenID_binaryToLong($this->bin);
        $s_prime = Auth_OpenID_longToBinary($this->lng);
        $this->assertEquals($this->lib->cmp($this->lng, $n_prime), 0);
        $this->assertTrue($this->bin == $s_prime);
    }
}

class Tests_Auth_OpenID_Base64ToLong extends PHPUnit_TestCase {
    var $num;
    var $b64;
    var $lib;

    function Tests_Auth_OpenID_Base64ToLong(&$lib, $b64, $num)
    {
        $this->lib = $lib;
        $this->b64 = $b64;
        $this->num = $num;
    }

    function runTest()
    {
        $actual = Auth_OpenID_base64ToLong($this->b64);
        $this->assertTrue($this->lib->cmp($this->num, $actual) == 0);
    }
}

class Tests_Auth_OpenID_LongToBase64 extends Tests_Auth_OpenID_Base64ToLong {
    function Tests_Auth_OpenID_LongToBase64(&$lib, $b64, $num)
    {
        $this->lib = $lib;
        $this->b64 = $b64;
        $this->num = $num;
    }

    function runTest()
    {
        $actual = Auth_OpenID_longToBase64($this->num);
        $this->assertEquals($this->b64, $actual);
    }
}

class Tests_Auth_OpenID_RandRange extends PHPUnit_TestCase {
    function Tests_Auth_OpenID_RandRange(&$lib)
    {
        $this->lib =& $lib;
    }

    function runTest()
    {
        $stop = $this->lib->pow(2, 128);
        $a = Auth_OpenID_randrange($stop);
        $b = Auth_OpenID_randrange($stop);

        $this->assertFalse($this->lib->cmp($b, $a) == 0, "Same: $a $b");

        $n = $this->lib->init(Tests_Auth_OpenID_maxint());
        $n = $this->lib->add($n, 1);

        // Make sure that we can generate random numbers that are
        // larger than platform int size
        $result = Auth_OpenID_randrange($n);

        // What can we say about the result?
    }
}

/**
 * Computes the maximum integer value for this PHP installation.
 *
 * @return int $max_int_value The maximum integer value for this
 * PHP installation
 */
function Tests_Auth_OpenID_maxint()
{
    /* assumes largest integer is of form 2^n - 1 */
    $to_test = pow(2, 16);
    while (1) {
        $last = $to_test;
        $to_test = 2 * $to_test;
        if (($to_test < $last) || (!is_int($to_test))) {
            return($last + ($last - 1));
        }
    }
}


class Tests_Auth_OpenID_BigMath extends PHPUnit_TestSuite {
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

    function Tests_Auth_OpenID_BigMath($name)
    {
        $this->setName($name);
        
        if (!defined('Auth_OpenID_NO_MATH_SUPPORT')) {
            $this->addTestSuite('Tests_Auth_OpenID_BigInt');

            $lib =& Auth_OpenID_getMathLib();
            $max = Tests_Auth_OpenID_maxint();
            $upper = defined('Tests_Auth_OpenID_thorough') ? 499 : 3;

            foreach (range(0, $upper) as $iteration) {
                $test = new Tests_Auth_OpenID_BinLongConvertRnd($lib, $max);
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
                $test = new Tests_Auth_OpenID_BinLongConvert($lib, $bin, $lng);
                $test->setName('BinLongConvert ' . bin2hex($bin));
                $this->addTest($test);
            }

            $count = defined('Tests_Auth_OpenID_thorough') ? -1 : 2;
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
                $test = new Tests_Auth_OpenID_Base64ToLong($lib, $b64, $num);
                $test->setName("B64->Long $num_s");
                $this->addTest($test);

                $test = new Tests_Auth_OpenID_LongToBase64($lib, $b64, $num);
                $test->setName("Long->B64 $num_s");
                $this->addTest($test);
            }

            $test = new Tests_Auth_OpenID_RandRange($lib);
            $test->setName('Big number randrange');
            $this->addTest($test);
        }
    }
}

?>