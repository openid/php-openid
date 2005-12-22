<?php

require_once('PHPUnit.php');

class Tests_OpenID_HMACSHA1_TestCase extends PHPUnit_TestCase {
    function Tests_OpenID_HMACSHA1_TestCase($name, $key, $data, $expected) {
        $this->setName($name);
        $this->key = $key;
        $this->data = $data;
        $this->expected = $expected;
    }

    function runTest() {
        $actual = OpenID_HMACSHA1($this->key, $this->data);
        $this->assertEquals($this->expected, $actual);
    }
}

class Tests_OpenID_HMACSHA1 extends PHPUnit_TestSuite {
    function _strConvert($s) {
        $repeat_pat = '/^0x([a-f0-9]{2}) repeated (\d+) times$/';
        if (preg_match($repeat_pat, $s, $match)) {
            $c = chr(hexdec($match[1]));
            $n = $match[2];
            $data = '';
            for ($i = 0; $i < $n; $i++) {
                $data .= $c;
            }
        } elseif (substr($s, 0, 2) == "0x") {
            $size = strlen($s);
            $data = '';
            for ($i = 2; $i < $size; $i += 2) {
                $byte = substr($s, $i, 2);
                $data .= chr(hexdec($byte));
            }
        } elseif (preg_match('/^"(.*)"$/', $s, $match)) {
            $data = $match[1];
        } else {
            trigger_error("Bad data format: $s", E_USER_ERROR);
        }
        return $data;
    }

    function _readTestCases() {
        $path = dirname(realpath(__FILE__));
        $hmac_test_data_file = $path . DIRECTORY_SEPARATOR . 'hmac.txt';
        $lines = file($hmac_test_data_file);
        if ($lines === FALSE) {
            trigger_error("Failed to open data file: $dh_test_data_file",
                       E_USER_ERROR);
            return FALSE;
        }

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
                if (!preg_match('/^([a-z0-9_-]+) =\s+(.*?)\n$/', $line, $match)) {
                    trigger_error("Bad test input: $line", E_USER_ERROR);
                }

                $c = count($match);
                if ($c != 3) {
                    trigger_error(
                        "Wrong number of elements in parsed case: $c",
                        E_USER_ERROR);
                    return FALSE;
                }

                $key = $match[1];
                $value = $match[2];
                $case[$key] = $value;
            }
        }

        if (count($case)) {
            $cases[] = $case;
        }

        // Normalize strings and check data integrity
        foreach ($cases as $case) {
            $case["key"] =
                Tests_OpenID_HMACSHA1::_strConvert($case["key"]);
            if (strlen($case["key"]) != $case["key_len"]) {
                trigger_error("Bad key length", E_USER_ERROR);
            }

            $case["data"] =
                Tests_OpenID_HMACSHA1::_strConvert($case["data"]);
            if (strlen($case["data"]) != $case["data_len"]) {
                trigger_error("Bad data length", E_USER_ERROR);
            }
            
            $case["digest"] =
                Tests_OpenID_HMACSHA1::_strConvert($case["digest"]);
            if (strlen($case["digest"]) != 20) {
                $l = strlen($case["digest"]);
                trigger_error("Bad digest length: $l", E_USER_ERROR);
            }
        }
        return $cases;
    }
}

?>
