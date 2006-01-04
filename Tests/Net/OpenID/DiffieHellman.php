<?php

require_once('PHPUnit.php');
require_once('Net/OpenID/DiffieHellman.php');

class Tests_Net_OpenID_DiffieHellman_CheckCases extends PHPUnit_TestCase {
    function Tests_Net_OpenID_DiffieHellman_CheckCases($cases, $n)
    {
        $this->cases = $cases;
        $this->n = $n;
    }

    function runTest()
    {
        $this->assertEquals($this->n, count($this->cases));
    }
}

class Tests_Net_OpenID_DiffieHellman_Private extends PHPUnit_TestCase {
    function Tests_Net_OpenID_DiffieHellman_Private($name, $input, $expected)
    {
        $this->setName("$name");
        $this->input = $input;
        $this->expected = $expected;
    }

    function runTest()
    {
        $dh = new Net_OpenID_DiffieHellman(NULL, NULL, $this->input);
        $this->assertEquals($this->expected, $dh->getPublicKey());
    }
}

class Tests_Net_OpenID_DiffieHellman_Exch extends PHPUnit_TestCase {
    function Tests_Net_OpenID_DiffieHellman_Exch($name, $p1, $p2, $shared)
    {
        $this->setName("$name");
        $this->p1 = $p1;
        $this->p2 = $p2;
        $this->shared = $shared;
    }

    function runTest()
    {
        $dh1 = new Net_OpenID_DiffieHellman(NULL, NULL, $this->p1);
        $dh2 = new Net_OpenID_DiffieHellman(NULL, NULL, $this->p2);
        $sh1 = $dh1->getSharedSecret($dh2->getPublicKey());
        $sh2 = $dh2->getSharedSecret($dh1->getPublicKey());
        $this->assertEquals($this->shared, $sh1);
        $this->assertEquals($this->shared, $sh2);
    }
}

class Tests_Net_OpenID_DiffieHellman extends PHPUnit_TestSuite {
    function _getLines($base)
    {
        $path = dirname(realpath(__FILE__));
        $dh_test_data_file = $path . DIRECTORY_SEPARATOR . $base;
        $lines = file($dh_test_data_file);
        if ($lines === FALSE) {
            trigger_error("Failed to open data file: $dh_test_data_file",
                          E_USER_ERROR);
        }
        return $lines;
    }

    function _readPrivateTestCases()
    {
        $lines = Tests_Net_OpenID_DiffieHellman::_getLines('dhpriv');
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

    function _readExchTestCases()
    {
        $lines = Tests_Net_OpenID_DiffieHellman::_getLines('dhexch');
        $cases = array();
        foreach ($lines as $line) {
            $case = array();
            if (!preg_match('/^(\d+) (\d+) (\d+)\n$/', $line, $case)) {
                trigger_error("Bad test input: $line", E_USER_ERROR);
            }

            $c = count($case);
            if ($c != 4) {
                trigger_error("Wrong number of elements in parsed case: $c",
                              E_USER_ERROR);
            }

            array_shift($case);
            $cases[] = $case;
        }
        return $cases;
    }

    function Tests_Net_OpenID_DiffieHellman($name)
    {
        $this->setName($name);

        $priv_cases = Tests_Net_OpenID_DiffieHellman::_readPrivateTestCases();
        $sanity = new Tests_Net_OpenID_DiffieHellman_CheckCases(
            $priv_cases, 29);
        $sanity->setName('Check parsing of priv test data');
        $this->addTest($sanity);

        $exch_cases = Tests_Net_OpenID_DiffieHellman::_readExchTestCases();
        $sanity = new Tests_Net_OpenID_DiffieHellman_CheckCases(
            $exch_cases, 25);
        $sanity->setName('Check parsing of exch test data');
        $this->addTest($sanity);

        if (defined('Net_OpenID_math_type')) {
            if (defined('Tests_Net_OpenID_DH_thorough')) {
                $npriv = count($priv_cases);
                $nexch = count($exch_cases);
            } else {
                $npriv = 1;
                $nexch = 3;
            }

            for ($i = 0; $i < $npriv; $i++) {
                $case = $priv_cases[$i];
                $one = new Tests_Net_OpenID_DiffieHellman_Private(
                    $i, $case[0], $case[1]);
                $this->addTest($one);
            }

            for ($i = 0; $i < $nexch; $i++) {
                $case = $exch_cases[$i];
                $one = new Tests_Net_OpenID_DiffieHellman_Exch(
                    $i, $case[0], $case[1], $case[2]);
                $this->addTest($one);
            }
        }
    }
}

?>
