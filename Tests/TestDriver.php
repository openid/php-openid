<?php

/**
 * A driver for the PHP OpenID unit tests.
 *
 * PHP versions 4 and 5
 *
 * LICENSE: See the COPYING file included in this distribution.
 *
 * @package OpenID
 * @author JanRain, Inc. <openid@janrain.com>
 * @copyright 2005 Janrain, Inc.
 * @license http://www.gnu.org/copyleft/lesser.html LGPL
 */

require_once 'PHPUnit.php';
require_once 'PHPUnit/GUI/HTML.php';

if (defined('E_STRICT')) {
    // PHP 5
    $_Net_OpenID_allowed_deprecation =
        array('var',
              'is_a()'
              );

    function ignoreDeprecation($errno, $errstr, $errfile, $errline)
    {
        // Handle http://bugs.php.net/bug.php?id=32428
        // Augment this
        // regular expression if the bug exists in another version.
        if (preg_match('/^5\.1\.1$/', phpversion()) && $errno == 2) {
            $allowed_files = array(array('/Net/OpenID/CryptUtil.php',
                                         'dl'),
                                   array('/Net/OpenID/OIDUtil.php',
                                         'parse_url'),
                                   array('/Net/OpenID/Store/FileStore.php',
                                         'mkdir'),
                                   array('/Net/OpenID/Store/FileStore.php',
                                         'stat'),
                                   array('/Net/OpenID/Store/FileStore.php',
                                         'fopen'),
                                   array('/Net/OpenID/Store/FileStore.php',
                                         'unlink'));

            foreach ($allowed_files as $entry) {
                list($afile, $msg) = $entry;
                $slen = strlen($afile);
                $slice = substr($errfile, strlen($errfile) - $slen, $slen);
                if ($slice == $afile && strpos($errstr, $msg) === 0) {
                    // Ignore this error
                    return;
                }
            }
        }

        global $_Net_OpenID_allowed_deprecation;

        switch ($errno) {
        case E_STRICT:
            // XXX: limit this to files we know about
            foreach ($_Net_OpenID_allowed_deprecation as $depr) {
                if (strpos($errstr, "$depr: Deprecated.") !== false) {
                    return;
                }
            }
            $pat = '/^Non-static method Net_OpenID_[A-Za-z0-9_]+' .
                   '::[A-Za-z0-9_]+\(\) (cannot|should not) be ' .
                   'called statically$/';
            if (preg_match($pat, $errstr)) {
                // Ignore warnings about static methods called
                // non-statically since marking them static would break
                // PHP 4 compatibility.
                return;
            }
        default:
            error_log("$errfile:$errline - Errno=$errno:\n[$errstr]");
        }
    }

    set_error_handler('ignoreDeprecation');
    error_reporting(E_STRICT | E_ALL);
} else {
    error_reporting(E_ALL);
}

/**
 * Load the tests that are defined in the named modules.
 *
 * If you have Tests/Foo.php which defines a test class called
 * Tests_Foo, the call would look like:
 *
 * loadTests('Tests/', array('Foo'))
 *
 * @param string $test_dir The root of the test hierarchy. Must end
 * with a /
 *
 * @param array $test_names The names of the modules in which the
 * tests are defined. This should not include the root of the test
 * hierarchy.
 */
function loadTests($test_dir, $test_names)
{
    $suites = array();

    foreach ($test_names as $filename) {
        $filename = $test_dir . $filename . '.php';
        $class_name = str_replace(DIRECTORY_SEPARATOR, '_', $filename);
        $class_name = basename($class_name, '.php');
        global_require_once($filename);
        $test = new $class_name($class_name);
        if (is_a($test, 'PHPUnit_TestCase')) {
            $test = new PHPUnit_TestSuite($class_name);
        }
        $suites[] = $test;
    }

    return $suites;
}

function global_require_once($name)
{
    require_once($name);
    foreach (get_defined_vars() as $k => $v) {
        if (!in_array($k, array('name', 'GLOBALS'))) {
            $GLOBALS[$k] = $v;
        }
    }
}

$_test_dir = 'Tests/Net/OpenID/';
$_test_names = array(
    'KVForm',
    'CryptUtil',
    'OIDUtil',
    'DiffieHellman',
    'HMACSHA1',
    'Association',
    'StoreTest',
    'Parse',
    'Consumer'
    );

function selectTests($names)
{
    global $_test_names;
    $lnames = array_map('strtolower', $names);
    $include = array();
    $exclude = array();
    foreach ($_test_names as $t) {
        $l = strtolower($t);
        if (in_array($l, $lnames)) {
            $include[] = $t;
        }

        if (in_array("/$l", $lnames)) {
            $exclude[] = $t;
        }
    }

    if (!count($include)) {
        $include = $_test_names;
    }

    return array_diff($include, $exclude);
}

// Load OpenID library tests
function loadSuite($names=null)
{
    global $_test_names;
    global $_test_dir;
    if ($names === null) {
        $names = $_test_names;
    }
    $selected = selectTests($names);
    return loadTests($_test_dir, $selected);
}
?>
