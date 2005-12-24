<?php

require_once('Tests/TestDriver.php');
require_once('PHPUnit/TestResult.php');

class TextTestResult extends PHPUnit_TestResult {
	function addError(&$test, &$t) {
		parent::addError($test, $t);
		echo "E";
	}

	function addFailure(&$test, &$t) {
		parent::addFailure($test, $t);
		echo "F";
	}

	function addPassedTest(&$test) {
		parent::addPassedTest($test);
		echo ".";
	}
	
	function dumpBadResults() {
		foreach ($this->failures() as $failure) {
			echo $failure->toString();
		}

		foreach ($this->errors() as $failure) {
			echo $failure->toString();
		}
	}
}

function microtime_float()
{
   list($usec, $sec) = explode(" ", microtime());
   return ((float)$usec + (float)$sec);
}

$suites = loadSuite();

$totals = array(
	'run' => 0,
	'error' => 0,
	'failure' => 0,
	'time' => 0
	);

foreach ($suites as $suite) {
	$name = $suite->getName();
	echo "==========================================
Test suite: $name
------------------------------------------
";

	$result = new TextTestResult();
	$before = microtime_float();
	$suite->run($result);
	$after = microtime_float();

	$run = $result->runCount();
	$error = $result->errorCount();
	$failure = $result->failureCount();
	$delta = $after - $before;
	$totals['run'] += $run;
	$totals['error'] += $error;
	$totals['failure'] += $failure;
	$totals['time'] += $delta;
	$human_delta = round($delta, 3);
	echo "\nRan $run tests in $human_delta seconds";
	if ($error || $failure) {
		echo " with $error errors, $failure failures";
	}
    echo "
==========================================

";
}

$before = microtime_float();
$run = $totals['run'];
$error = $totals['error'];
$failure = $totals['failure'];
$time = round($totals['time'], 3);
echo "Ran a total of $run tests in $time seconds with $error errors, $failure failures\n";
if ($totals['error'] || $totals['failure']) {
	exit(1);
}

?>