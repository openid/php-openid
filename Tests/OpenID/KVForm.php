<?php

require_once('PHPUnit.php');
require_once('OpenID/KVForm.php');

class Tests_OpenID_KVForm_TestCase extends PHPUnit_TestCase {
	function Tests_OpenID_KVForm_TestCase($arr, $str, $lossy) {
		$this->arr = $arr;
		$this->str = $str;
		$this->lossy = $lossy;
	}

	function runTest() {
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
	}
}

class Tests_OpenID_KVForm_TestCase_Null extends PHPUnit_TestCase {
	function Tests_OpenID_KVForm_TestCase_Null($arr) {
		$this->arr = $arr;
	}

	function runTest() {
		$serialized = OpenID_KVForm::arrayToKV($this->arr);
		$this->assertTrue($serialized === NULL);
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
				  ),
			array("name" => "empty (double newline)", 
				  "str" => "\n\n",
				  "arr" => array(),
				  "lossy" => "str",
				  ),
			array("name" => "empty (no colon)", 
				  "str" => "East is least\n",
				  "arr" => array(),
				  "lossy" => "str",
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
				  ),
			array("name" => "whitespace at front of value", 
				  "str" => "major: computer science\n",
				  "arr" => array('major'=>'computer science'),
				  "lossy" => "str",
				  ),
			array("name" => "whitespace around key and value", 
				  "str" => " dorm : east \n",
				  "arr" => array('dorm'=>'east'),
				  "lossy" => "str",
				  ),
			array("name" => "missing trailing newline", 
				  "str" => "e^(i*pi)+1:0",
				  "arr" => array('e^(i*pi)+1'=>'0'),
				  "lossy" => "str",
				  ),
			array("name" => "missing trailing newline (two key)", 
				  "str" => "east:west\nnorth:south",
				  "arr" => array('east'=>'west',
								 'north'=>'south'),
				  "lossy" => "str",
				  ),
			array("name" => "colon in key",
				  "arr" => array("k:k" => 'v'),
				  ),
			array("name" => "newline in key",
				  "arr" => array("k\nk" => 'v'),
				  ),
			array("name" => "newline in value",
				  "arr" => array('k' => "v\nv"),
				  ),
			array("name" => "array whitespace",
				  "arr" => array(" k " => "v"),
				  "lossy" => "both",
				  "str" => " k :v\n",
				  ),
			);

		foreach ($testdata_list as $testdata) {
			$arr = $testdata["arr"];
			$str = $testdata["str"];
			if (isset($str)) {
				$lossy = $testdata["lossy"];
				if (!isset($lossy)) {
					$lossy = 'neither';
				}					
				$test = new Tests_OpenID_KVForm_TestCase($arr, $str, $lossy);
			} else {
				$test = new Tests_OpenID_KVForm_TestCase_Null($arr);
			}
			$test->setName($testdata["name"]);
			$this->addTest($test);
		}
	}
}

?>
