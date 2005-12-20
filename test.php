<?php

require_once('PHPUnit.php');
require_once('PHPUnit/TestSuite.php');
require_once('PHPUnit/GUI/HTML.php');

$prefix = 'Tests/OpenID/';

$test_names = array(
	'KVForm'=>FALSE,
	'CryptUtil'=>TRUE,
	);

$suites = array();

foreach ($test_names as $filename => $introspect) {
	$filename = $prefix . $filename . '.php';
	$className = str_replace(DIRECTORY_SEPARATOR, '_', $filename);
	$className = basename($className,'.php');
	include_once($filename);
	if ($introspect) {
		$suites[] = new PHPUnit_TestSuite($className);
	} else {
		$suites[] = new $className($className);
	}
}

$gui = new PHPUnit_GUI_HTML();
$gui->addSuites($suites);
$gui->show();

?>
