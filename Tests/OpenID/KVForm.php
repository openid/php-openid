<?php

require_once('PHPUnit.php');
require_once('OpenID/KVForm.php');

$Tests_OpenID_KVForm_errors = NULL;

/**
 * Count the number of logged errors
 */
function Tests_OpenID_KVForm_err($errno, $errmsg, $filename, $linenum, $vars) {
	global $Tests_OpenID_KVForm_errors;
	$Tests_OpenID_KVForm_errors[] = $errmsg;
}

class Tests_OpenID_KVForm_TestCase extends PHPUnit_TestCase {

	function Tests_OpenID_KVForm_TestCase($arr, $str, $lossy, $errs) {
		$this->arr = $arr;
		$this->str = $str;
		$this->lossy = $lossy;
		$this->errs = $errs;
	}

	function runTest() {
		// Re-set the number of logged errors
		global $Tests_OpenID_KVForm_errors;
		$Tests_OpenID_KVForm_errors = array();

		set_error_handler("Tests_OpenID_KVForm_err");

		// Do one parse, after which arrayToKV and kvToArray should be
		// inverses.
		$parsed1 = OpenID_KVForm::kvToArray($this->str);
		$serial1 = OpenID_KVForm::arrayToKV($this->arr);

		if ($this->lossy == "neither" || $this->lossy == "str") {
			$this->assertEquals($this->arr, $parsed1);
		}
			
		if ($this->lossy == "neither" || $this->lossy == "arr") {
			$this->assertEquals($this->str, $serial1);
		}

		$parsed2 = OpenID_KVForm::kvToArray($serial1);
		$serial2 = OpenID_KVForm::arrayToKV($parsed1);

		// Round-trip both
		$parsed3 = OpenID_KVForm::kvToArray($serial2);
		$serial3 = OpenID_KVForm::arrayToKV($parsed2);

		$this->assertEquals($serial2, $serial3);

		// Check to make sure that they're inverses.
		$this->assertEquals($parsed2, $parsed3);

		// Check to make sure we have the expected number of logged errors
		$this->assertEquals($this->errs, count($Tests_OpenID_KVForm_errors));

		restore_error_handler();
	}
}

class Tests_OpenID_KVForm_TestCase_Null extends PHPUnit_TestCase {
	function Tests_OpenID_KVForm_TestCase_Null($arr, $errs) {
		$this->arr = $arr;
		$this->errs = $errs;
	}

	function runTest() {
		// Re-set the logged errors
		global $Tests_OpenID_KVForm_errors;
		$Tests_OpenID_KVForm_errors = array();

		set_error_handler("Tests_OpenID_KVForm_err");

		$serialized = OpenID_KVForm::arrayToKV($this->arr);
		$this->assertTrue($serialized === NULL);

		// Check to make sure we have the expected number of logged errors
		$this->assertEquals($this->errs, count($Tests_OpenID_KVForm_errors));

		restore_error_handler();
	}
}

class Tests_OpenID_KVForm extends PHPUnit_TestSuite {
	function Tests_OpenID_KVForm($name) {
		$this->setName($name);
		$testdata_list = array(
			array("name" => "simple", 
				  "str" => "college:harvey mudd\n",
				  "arr" => array("college" => "harvey mudd"),
				  ),
			array("name" => "empty", 
				  "str" => "",
				  "arr" => array(),
				  ),
			array("name" => "empty (just newline)", 
				  "str" => "\n",
				  "arr" => array(),
				  "lossy" => "str",
				  "errors" => 1,
				  ),
			array("name" => "empty (double newline)", 
				  "str" => "\n\n",
				  "arr" => array(),
				  "lossy" => "str",
				  "errors" => 2,
				  ),
			array("name" => "empty (no colon)", 
				  "str" => "East is least\n",
				  "arr" => array(),
				  "lossy" => "str",
				  "errors" => 1,
				  ),
			array("name" => "two keys", 
				  "str" => "city:claremont\nstate:CA\n",
				  "arr" => array('city' => 'claremont',
								 'state' => 'CA'),
				  ),
			array("name" => "real life", 
				  "str" => "is_valid:true\ninvalidate_handle:" .
				  "{HMAC-SHA1:2398410938412093}\n",
				  "arr" => array('is_valid' => 'true',
								 'invalidate_handle' =>
								 '{HMAC-SHA1:2398410938412093}'),
				  ),
			array("name" => "empty key and value", 
				  "str" => ":\n",
				  "arr" => array(''=>''),
				  ),
			array("name" => "empty key, not value", 
				  "str" => ":missing key\n",
				  "arr" => array(''=>'missing key'),
				  ),
			array("name" => "whitespace at front of key",
				  "str" => " street:foothill blvd\n",
				  "arr" => array('street'=>'foothill blvd'),
				  "lossy" => "str",
				  "errors" => 1,
				  ),
			array("name" => "whitespace at front of value", 
				  "str" => "major: computer science\n",
				  "arr" => array('major'=>'computer science'),
				  "lossy" => "str",
				  "errors" => 1,
				  ),
			array("name" => "whitespace around key and value", 
				  "str" => " dorm : east \n",
				  "arr" => array('dorm'=>'east'),
				  "lossy" => "str",
				  "errors" => 2,
				  ),
			array("name" => "missing trailing newline", 
				  "str" => "e^(i*pi)+1:0",
				  "arr" => array('e^(i*pi)+1'=>'0'),
				  "lossy" => "str",
				  "errors" => 1,
				  ),
			array("name" => "missing trailing newline (two key)", 
				  "str" => "east:west\nnorth:south",
				  "arr" => array('east'=>'west',
								 'north'=>'south'),
				  "lossy" => "str",
				  "errors" => 1,
				  ),
			array("name" => "colon in key",
				  "arr" => array("k:k" => 'v'),
				  "errors" => 1,
				  ),
			array("name" => "newline in key",
				  "arr" => array("k\nk" => 'v'),
				  "errors" => 1,
				  ),
			array("name" => "newline in value",
				  "arr" => array('k' => "v\nv"),
				  "errors" => 1,
				  ),
			array("name" => "array whitespace",
				  "arr" => array(" k " => "v"),
				  "lossy" => "both",
				  "str" => " k :v\n",
				  "errors" => 2,
				  ),
			);

		foreach ($testdata_list as $testdata) {
			$arr = $testdata["arr"];
			$str = $testdata["str"];
			$errs = $testdata["errors"];
			if (!isset($errs)) {
				$errs = 0;
			}
			if (isset($str)) {
				$lossy = $testdata["lossy"];
				if (!isset($lossy)) {
					$lossy = 'neither';
				}					
				$test = new Tests_OpenID_KVForm_TestCase(
					$arr, $str, $lossy, $errs);
			} else {
				$test = new Tests_OpenID_KVForm_TestCase_Null($arr, $errs);
			}
			$test->setName($testdata["name"]);
			$this->addTest($test);
		}
	}
}

?>
