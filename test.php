<?php

require_once('PHPUnit.php');
require_once('PHPUnit/TestSuite.php');
require_once('PHPUnit/GUI/HTML.php');

$prefix = 'Tests/OpenID/';

$test_names = array(
	'KVForm',
	'CryptUtil',
	);

$suites = array();

foreach ($test_names as $filename) {
	$filename = $prefix . $filename . '.php';
	$className = str_replace(DIRECTORY_SEPARATOR, '_', $filename);
	$className = basename($className,'.php');
	include_once($filename);
	$test = new $className($className);
	if (is_a($test, 'PHPUnit_TestCase')) {
		$test = new PHPUnit_TestSuite($className);
	}
	$suites[] = $test;
}

$gui = new PHPUnit_GUI_HTML();
$gui->addSuites($suites);
$gui->show();

?>
