<?php

/**
 * Tests for the core of the PHP Yadis library.
 */

require_once 'PHPUnit.php';
require_once 'Services/Yadis/Yadis.php';
require_once 'Tests/Services/Yadis/TestUtil.php';

class Tests_Services_Yadis_DiscoveryTest extends PHPUnit_TestCase {

    function Tests_Services_Yadis_DiscoveryTest($input_url, $redir_uri,
                                                $xrds_uri, $num)
    {
        $this->input_url = $input_url;
        $this->redir_uri = $redir_uri;
        $this->xrds_uri = $xrds_uri;
        $this->num = $num;
    }

    function getName()
    {
        return "Yadis discovery test ".$this->num;
    }

    function runTest()
    {
        $http_response = null;
        $fetcher = Services_Yadis_Yadis::getHTTPFetcher();
        $y = Services_Yadis_Yadis::discover(
             $this->input_url, $http_response, $fetcher);
        $this->assertTrue($y !== null);

        // Compare parts of returned Yadis object to expected URLs.
        $this->assertEquals($this->redir_uri, $y->uri);

        if ($this->xrds_uri) {
            $this->assertEquals($this->xrds_uri, $y->xrds_uri);
            // Compare contents of actual HTTP GET with that of Yadis
            // response.
            $f = Services_Yadis_Yadis::getHTTPFetcher();
            $response = $f->get($this->xrds_uri);

            $this->assertEquals($response->body, $y->body);
        } else {
            $this->assertTrue($y->xrds_uri === null);
        }
    }
}

class Tests_Services_Yadis_Yadis extends PHPUnit_TestSuite {

    function getName()
    {
        return "Tests_Services_Yadis_Yadis";
    }

    function parseTests($data)
    {
        $cases = explode("\n", $data);
        $tests = array();

        foreach ($cases as $line) {
            if ($line && ($line[0] != "#")) {
                $tests[] = explode("\t", $line, 3);
            }
        }

        return $tests;
    }

    function Tests_Services_Yadis_Yadis()
    {
        $test_data = Tests_Services_Yadis_readdata('manifest.txt');

        $test_cases = $this->parseTests($test_data);

        $i = 0;
        foreach ($test_cases as $case) {
            $i++;
            list($input, $redir, $xrds) = $case;
            $this->addTest(new Tests_Services_Yadis_DiscoveryTest($input,
                                                                  $redir,
                                                                  $xrds, $i));
        }
    }

}

?>