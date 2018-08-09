<?php

/**
 * Tests for the KVForm module.
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

require_once 'Auth/OpenID/KVForm.php';

global $_Tests_Auth_OpenID_kverrors;
$_Tests_Auth_OpenID_kverrors = null;

/**
 * Keep a list of the logged errors
 */
function Tests_Auth_OpenID_kvHandleError($errno, $errmsg)
{
    global $_Tests_Auth_OpenID_kverrors;
    $_Tests_Auth_OpenID_kverrors[] = $errmsg;
}


class Tests_Auth_OpenID_KVForm_TestCase extends PHPUnit_Framework_TestCase {
    var $errs;

    function runTest()
    {
        // Re-set the number of logged errors
        global $_Tests_Auth_OpenID_kverrors;
        $_Tests_Auth_OpenID_kverrors = [];

        set_error_handler("Tests_Auth_OpenID_kvHandleError");

        $this->_runTest();

        // Check to make sure we have the expected number of logged errors
        //$this->assertEquals($this->errs, count($_Tests_Auth_OpenID_kverrors));

        restore_error_handler();
    }

    function _runTest()
    {
        trigger_error('Must be overridden', E_USER_ERROR);
    }
}

class Tests_Auth_OpenID_KVForm_TestCase_Parse
extends Tests_Auth_OpenID_KVForm_TestCase {
    function __construct(
        $arr, $str, $lossy, $errs)
    {

        $this->arr = $arr;
        $this->str = $str;
        $this->lossy = $lossy;
        $this->errs = $errs;
    }

    function _runTest()
    {
        // Do one parse, after which arrayToKV and kvToArray should be
        // inverses.
        $parsed1 = Auth_OpenID_KVForm::toArray($this->str);
        $serial1 = Auth_OpenID_KVForm::fromArray($this->arr);

        if ($this->lossy == "neither" || $this->lossy == "str") {
            $this->assertEquals($this->arr, $parsed1, "str was lossy");
        }

        if ($this->lossy == "neither" || $this->lossy == "arr") {
            $this->assertEquals($this->str, $serial1, "array was lossy");
        }

        $parsed2 = Auth_OpenID_KVForm::toArray($serial1);
        $serial2 = Auth_OpenID_KVForm::fromArray($parsed1);

        // Round-trip both
        $parsed3 = Auth_OpenID_KVForm::toArray($serial2);
        $serial3 = Auth_OpenID_KVForm::fromArray($parsed2);

        $this->assertEquals($serial2, $serial3, "serialized forms differ");

        // Check to make sure that they're inverses.
        $this->assertEquals($parsed2, $parsed3, "parsed forms differ");

    }
}

class Tests_Auth_OpenID_KVForm_TestCase_Null
extends Tests_Auth_OpenID_KVForm_TestCase {
    function __construct($arr, $errs)
    {
        $this->arr = $arr;
        $this->errs = $errs;
    }

    function _runTest()
    {
        $serialized = Auth_OpenID_KVForm::fromArray($this->arr);
        $this->assertTrue($serialized === null,
                          'serialization unexpectedly succeeded');
    }
}

class Tests_Auth_OpenID_KVForm extends PHPUnit_Framework_TestSuite {
    function __construct($name)
    {
        $this->setName($name);
        $testdata_list = [
            [
                "name" => "simple",
                "str" => "college:harvey mudd\n",
                "arr" => ["college" => "harvey mudd"],
            ],
            [
                "name" => "empty",
                "str" => "",
                "arr" => [],
            ],
            [
                "name" => "empty (just newline)",
                "str" => "\n",
                "arr" => [],
                "lossy" => "str",
                "errors" => 1,
            ],
            [
                "name" => "empty (double newline)",
                "str" => "\n\n",
                "arr" => [],
                "lossy" => "str",
                "errors" => 2,
            ],
            [
                "name" => "empty (no colon)",
                "str" => "East is least\n",
                "arr" => [],
                "lossy" => "str",
                "errors" => 1,
            ],
            [
                "name" => "two keys",
                "str" => "city:claremont\nstate:CA\n",
                "arr" => [
                    'city' => 'claremont',
                    'state' => 'CA',
                ],
            ],
            [
                "name" => "real life",
                "str" => "is_valid:true\ninvalidate_handle:" .
                         "{HMAC-SHA1:2398410938412093}\n",
                "arr" => [
                    'is_valid' => 'true',
                    'invalidate_handle' =>
                        '{HMAC-SHA1:2398410938412093}',
                ],
            ],
            [
                "name" => "empty key and value",
                "str" => ":\n",
                "arr" => ['' => ''],
            ],
            [
                "name" => "empty key, not value",
                "str" => ":missing key\n",
                "arr" => ['' => 'missing key'],
            ],
            [
                "name" => "whitespace at front of key",
                "str" => " street:foothill blvd\n",
                "arr" => ['street' => 'foothill blvd'],
                "lossy" => "str",
                "errors" => 1,
            ],
            [
                "name" => "whitespace at front of value",
                "str" => "major: computer science\n",
                "arr" => ['major' => 'computer science'],
                "lossy" => "str",
                "errors" => 1,
            ],
            [
                "name" => "whitespace around key and value",
                "str" => " dorm : east \n",
                "arr" => ['dorm' => 'east'],
                "lossy" => "str",
                "errors" => 2,
            ],
            [
                "name" => "missing trailing newline",
                "str" => "e^(i*pi)+1:0",
                "arr" => ['e^(i*pi)+1' => '0'],
                "lossy" => "str",
                "errors" => 1,
            ],
            [
                "name" => "missing trailing newline (two key)",
                "str" => "east:west\nnorth:south",
                "arr" => [
                    'east' => 'west',
                    'north' => 'south',
                ],
                "lossy" => "str",
                "errors" => 1,
            ],
            [
                "name" => "colon in key",
                "arr" => ["k:k" => 'v'],
                "errors" => 1,
            ],
            [
                "name" => "newline in key",
                "arr" => ["k\nk" => 'v'],
                "errors" => 1,
            ],
            [
                "name" => "newline in value",
                "arr" => ['k' => "v\nv"],
                "errors" => 1,
            ],
            [
                "name" => "array whitespace",
                "arr" => [" k " => "v"],
                "lossy" => "both",
                "str" => " k :v\n",
                "errors" => 2,
            ],
            [
                "name" => "array ordering 1",
                "arr" => [
                    "a" => "x",
                    "b" => "x",
                    "c" => "x",
                ],
                "str" => "a:x\nb:x\nc:x\n",
            ],
            [
                "name" => "array ordering 2",
                "arr" => [
                    "a" => "x",
                    "c" => "x",
                    "b" => "x",
                ],
                "str" => "a:x\nc:x\nb:x\n",
            ],
        ];

        foreach ($testdata_list as $testdata) {
            if (isset($testdata['str'])) {
                $str = $testdata['str'];
            } else {
                $str = null;
            }

            $arr = $testdata["arr"];

            if (isset($testdata['errors'])) {
                $errs = $testdata["errors"];
            } else {
                $errs = 0;
            }

            if (is_null($str)) {
                $test = new Tests_Auth_OpenID_KVForm_TestCase_Null($arr, $errs);
            } else {
                if (isset($testdata['lossy'])) {
                    $lossy = $testdata["lossy"];
                } else {
                    $lossy = 'neither';
                }
                $test = new Tests_Auth_OpenID_KVForm_TestCase_Parse(
                    $arr, $str, $lossy, $errs);
            }
            $test->setName($testdata["name"]);
            $this->addTest($test);
        }
    }
}


