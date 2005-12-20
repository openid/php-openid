<?php

require_once('PHPUnit.php');
require_once('PHPUnit/GUI/HTML.php');

function loadTests($test_dir, $test_names) {
	$suites = array();

	foreach ($test_names as $filename) {
		$filename = $test_dir . $filename . '.php';
		$class_name = str_replace(DIRECTORY_SEPARATOR, '_', $filename);
		$class_name = basename($class_name, '.php');
		include_once($filename);
		$test = new $class_name($class_name);
		if (is_a($test, 'PHPUnit_TestCase')) {
			$test = new PHPUnit_TestSuite($class_name);
		}
		$suites[] = $test;
	}

	return $suites;
}

$test_dir = 'Tests' . DIRECTORY_SEPARATOR . 'OpenID' . DIRECTORY_SEPARATOR;
$test_names = array(
	'KVForm',
	'CryptUtil',
	);

$suites = loadTests($test_dir, $test_names);

$gui = new PHPUnit_GUI_HTML();
$gui->addSuites($suites);
$gui->show();

?>
