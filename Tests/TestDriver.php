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

error_reporting(E_ALL);

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

        $tc_array_name = $class_name . '_other';
        if (array_key_exists($tc_array_name, $GLOBALS) &&
            is_array($GLOBALS[$tc_array_name])) {
            foreach ($GLOBALS[$tc_array_name] as $tc) {
                $test->addTest($tc); // new PHPUnit_TestSuite($tc));
            }
        }

        $suites[] = $test;
    }

    return $suites;
}

function global_require_once($name)
{
    require_once $name;
    foreach (get_defined_vars() as $k => $v) {
        if (!in_array($k, array('name', 'GLOBALS'))) {
            $GLOBALS[$k] = $v;
        }
    }
}

$_test_dir = 'Tests/Auth/OpenID/';
$_test_names = array(
    'Association',
    'BigMath',
    'Consumer',
    'CryptUtil',
    'DiffieHellman',
    'HMACSHA1',
    'KVForm',
    'Util',
    'Parse',
    'StoreTest',
    'Server',
    'TrustRoot',
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
