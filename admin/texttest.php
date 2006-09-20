<?php

require_once 'Tests/TestDriver.php';
require_once 'PHPUnit/TestResult.php';

class TextTestResult extends PHPUnit_TestResult {
    function addError(&$test, &$t)
    {
        parent::addError($test, $t);
        echo "E";
    }

    function addFailure(&$test, &$t)
    {
        parent::addFailure($test, $t);
        echo "F";
    }

    function addPassedTest(&$test)
    {
        parent::addPassedTest($test);
        echo ".";
    }

    function dumpBadResults()
    {
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

// Drop $argv[0] (command name)
array_shift($argv);

// ******** Math library selection ***********

$t = array_search('--no-math', $argv);
if ($t !== false && $t !== null) {
    define('Auth_OpenID_NO_MATH_SUPPORT', true);
} else {
    $math_libs = array();
    foreach ($argv as $arg) {
        $ret = preg_match('/^--math-lib=(.*)$/', $arg, $matches);
        if ($ret) {
            $math_libs[] = $matches[1];
        }
    }

    if ($math_libs) {
        require_once('Auth/OpenID/BigMath.php');
        $new_extensions = array();
        foreach ($math_libs as $lib) {
            foreach ($_Auth_OpenID_math_extensions as $ext) {
                if ($ext['extension'] == $lib) {
                    $new_extensions[] = $ext;
                }
            }
        }
        if ($new_extensions) {
            $_Auth_OpenID_math_extensions = $new_extensions;
        } else {
            trigger_error(var_export($math_libs, true), E_USER_ERROR);
        }
    }
}

// ******** End math library selection **********

$t = array_search('--thorough', $argv);
if ($t !== false && $t !== null) {
    define('Tests_Auth_OpenID_thorough', true);
}

$suites = loadSuite($argv);

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

    $failures = $result->failures();
    foreach($failures as $failure) {
        $test = $failure->failedTest();
        $testName = $test->getName();
        $exception = $failure->thrownException();
        echo "* Failure in $testName: $exception

";
    }
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