<?php

/**
 * Tests for the HMAC-SHA1 utility functions used by the OpenID
 * library.
 *
 * PHP versions 4 and 5
 *
 * LICENSE: See the COPYING file included in this distribution.
 *
 * @package OpenID
 * @author JanRain, Inc. <openid@janrain.com>
 * @copyright 2005-2008 Janrain, Inc.
 * @license http://www.apache.org/licenses/LICENSE-2.0 Apache
 */

require_once 'PHPUnit.php';
require_once 'Auth/OpenID/HMAC.php';
require_once 'Tests/Auth/OpenID/TestUtil.php';

class Tests_Auth_OpenID_HMAC_TestCase extends PHPUnit_TestCase {
    function Tests_Auth_OpenID_HMAC_TestCase(
        $name, $key, $data, $expected, $hmac_func)
    {

        $this->setName($name);
        $this->key = $key;
        $this->data = $data;
        $this->expected = $expected;
        $this->hmac_func = $hmac_func;
    }

    function runTest()
    {
        $actual = call_user_func($this->hmac_func, $this->key, $this->data);
        $this->assertEquals($this->expected, $actual);
    }
}

class Tests_Auth_OpenID_HMAC extends PHPUnit_TestSuite {
    function _strConvert($s)
    {
        $repeat_pat = '/^0x([a-f0-9]{2}) repeated (\d+) times$/';
        if (preg_match($repeat_pat, $s, $match)) {
            $c = chr(hexdec($match[1]));
            $n = $match[2];
            $data = '';
            for ($i = 0; $i < $n; $i++) {
                $data .= $c;
            }
        } elseif (substr($s, 0, 2) == "0x") {
            $data = pack('H*', substr($s, 2, strlen($s) - 1));
        } elseif (preg_match('/^"(.*)"$/', $s, $match)) {
            $data = $match[1];
        } else {
            trigger_error("Bad data format: $s", E_USER_ERROR);
        }
        return $data;
    }

    function _readTestCases($test_file_name)
    {
        $lines = Tests_Auth_OpenID_readlines($test_file_name);
        $cases = array();
        $case = array();
        foreach ($lines as $line) {
            if ($line{0} == "#") {
                continue;
            }

            // Blank line separates test cases
            if ($line == "\n") {
                $cases[] = $case;
                $case = array();
            } else {
                $match = array();
                $pat = '/^([a-z0-9_-]+) =\s+(.*?)\n$/';
                if (!preg_match($pat, $line, $match)) {
                    trigger_error("Bad test input: $line", E_USER_ERROR);
                }

                $c = count($match);
                if ($c != 3) {
                    trigger_error(
                        "Wrong number of elements in parsed case: $c",
                        E_USER_ERROR);
                    return false;
                }

                $key = $match[1];
                $value = $match[2];
                $case[$key] = $value;
            }
        }

        if (count($case)) {
            $cases[] = $case;
        }

        $final = array();

        // Normalize strings and check data integrity
        foreach ($cases as $case) {
            $clean = array();
            $clean["key"] =
                Tests_Auth_OpenID_HMAC::_strConvert($case["key"]);
            if (Auth_OpenID::bytes($clean["key"]) != $case["key_len"]) {
                trigger_error("Bad key length", E_USER_ERROR);
            }

            $clean["data"] =
                Tests_Auth_OpenID_HMAC::_strConvert($case["data"]);
            if (Auth_OpenID::bytes($clean["data"]) != $case["data_len"]) {
                trigger_error("Bad data length", E_USER_ERROR);
            }

            $clean["digest"] =
                Tests_Auth_OpenID_HMAC::_strConvert($case["digest"]);
            if (Auth_OpenID::bytes($clean["digest"]) != 20) {
                $l = Auth_OpenID::bytes($clean["digest"]);
                trigger_error("Bad digest length: $l", E_USER_ERROR);
            }

            $clean['test_case'] = $case['test_case'];

            $final[] = $clean;
        }
        return $final;
    }

    function Tests_Auth_OpenID_HMAC($name)
    {
        $this->setName($name);
        foreach (array('Auth_OpenID_HMACSHA1' => 'hmac-sha1.txt')
                 as $hash_func => $filename) {
            $cases = $this->_readTestCases('hmac-sha1.txt');
            foreach ($cases as $case) {
                $test = new Tests_Auth_OpenID_HMAC_TestCase(
                    $case['test_case'],
                    $case['key'],
                    $case['data'],
                    $case['digest'],
                    $hash_func);

                $digest = $case['digest'];
                $this->_addTestByValue($test);
            }
        }
    }

    function _addTestByValue($test) {
        $this->addTest($test);
    }
}

?>
