<?php

require_once('PHPUnit.php');
require_once('OpenID/DiffieHellman.php');

class Tests_OpenID_DiffieHellman_CheckCases extends PHPUnit_TestCase {
    function Tests_OpenID_DiffieHellman_CheckCases($cases) {
        $this->cases = $cases;
    }

    function runTest() {
        $this->assertEquals(29, count($this->cases));
    }
}

class Tests_OpenID_DiffieHellman_OneCase extends PHPUnit_TestCase {
    function Tests_OpenID_DiffieHellman_OneCase($name, $input, $expected) {
        $this->setName("$name");
        $this->input = $input;
        $this->expected = $expected;
    }

    function runTest() {
        $dh = new OpenID_DiffieHellman(NULL, NULL, $this->input);
        $this->assertEquals($this->expected, $dh->getPublicKey());
    }
}

class Tests_OpenID_DiffieHellman extends PHPUnit_TestSuite {
    function _readTestCases() {
        $path = dirname(realpath(__FILE__));
        $dh_test_data_file = $path . DIRECTORY_SEPARATOR . 'dhpriv';
        $lines = file($dh_test_data_file);
        if ($lines === FALSE) {
            trigger_error("Failed to open data file: $dh_test_data_file",
                          E_USER_ERROR);
        }

        $cases = array();
        foreach ($lines as $line) {
            $case = array();
            if (!preg_match('/^(\d+) (\d+)\n$/', $line, $case)) {
                trigger_error("Bad test input: $line", E_USER_ERROR);
            }

            $c = count($case);
            if ($c != 3) {
                trigger_error("Wrong number of elements in parsed case: $c",
                              E_USER_ERROR);
            }

            array_shift($case);
            $cases[] = $case;
        }

        return $cases;
    }

    function Tests_OpenID_DiffieHellman($name) {
        $this->setName($name);

        $cases = Tests_OpenID_DiffieHellman::_readTestCases();
        $sanity = new Tests_OpenID_DiffieHellman_CheckCases($cases);
        $sanity->setName('Check parsing of test data');
        $this->addTest($sanity);

        for ($i = 0; $i < count($cases); $i++) {
            $case = $cases[$i];
            $one = new Tests_OpenID_DiffieHellman_OneCase(
                $i, $case[0], $case[1]);
            $this->addTest($one);
        }
    }
}

?>