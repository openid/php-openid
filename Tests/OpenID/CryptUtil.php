<?php

require_once('PHPUnit.php');
require_once('OpenID/CryptUtil.php');

class Tests_OpenID_CryptUtil extends PHPUnit_TestCase {
	function test_length() {
		$cases = array(1, 10, 255);
		foreach ($cases as $length) {
			$data = OpenID_CryptUtil::getBytes($length);
			$this->assertEquals(strlen($data), $length);
		}
	}

	function test_different() {
		$num_iterations = 100;
		$data_length = 20;

		$data = OpenID_CryptUtil::getBytes($num_iterations);
		for ($i = 0; $i < $num_iterations; $i++) {
			$last = $data;
			$data = OpenID_CryptUtil::getBytes($num_iterations);
			$this->assertFalse($data == $last);
		}
	}
}

?>