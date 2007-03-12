<?php

require_once "PHPUnit.php";
require_once "Tests/Auth/Yadis/DiscoverData.php";
require_once "Auth/Yadis/Yadis.php";
require_once "Auth/Yadis/HTTPFetcher.php";

global $__status_header_re;
$__status_header_re = '/Status: (\d+) .*?$/m';

function mkResponse($data)
{
    global $__status_header_re;

    $matches = array();
    $status_mo = preg_match($__status_header_re, $data, $matches);
    list($headers_str, $body) = explode("\n\n", $data, 2);
    $headers = array();
    foreach (explode("\n", $headers_str) as $line) {
        list($k, $v) = explode(":", $line, 2);
        $k = strtolower(trim($k));
        $v = trim($v);
        $headers[$k] = $v;
    }
    $status = intval($matches[1]);
    $r = new Auth_Yadis_HTTPResponse(null, $status, $headers, $body);
    return $r;
}
class TestFetcher {
    function TestFetcher($base_url)
    {
        $this->base_url = $base_url;
    }

    function get($url, $headers = null)
    {
        $current_url = $url;
        while (true) {
            $parsed = parse_url($current_url);
            $path = substr($parsed['path'], 1);
            $data = generateSample($path, $this->base_url);

            if ($data === null) {
                return new Auth_Yadis_HTTPResponse($current_url,
                                                       404,
                                                       array(),
                                                       '');
            }

            $response = mkResponse($data);
            if (in_array($response->status, array(301, 302, 303, 307))) {
                $current_url = $response->headers['location'];
            } else {
                $response->final_url = $current_url;
                return $response;
            }
        }
    }
}

class MockFetcher {
    function MockFetcher() {
        $this->count = 0;
    }

    function get($uri, $headers = null, $body = null)
    {
        $this->count++;
        if ($this->count == 1) {
            $headers = array(strtolower('X-XRDS-Location') . ': http://unittest/404');
            return new Auth_Yadis_HTTPResponse($uri, 200, $headers, '');
        } else {
            return new Auth_Yadis_HTTPResponse($uri, 404);
        }
    }
}

class TestSecondGet extends PHPUnit_TestCase {
    function test_404()
    {
        $uri = "http://something.unittest/";
        $response = null;
        $fetcher = new MockFetcher();
        $this->assertTrue(
               Auth_Yadis_Yadis::discover($uri, $response, $fetcher) === null);
    }
}

class _TestCase extends PHPUnit_TestCase {
    var $base_url = 'http://invalid.unittest/';

    function _TestCase($input_name, $id_name, $result_name, $success)
    {
        $this->input_name = $input_name;
        $this->id_name = $id_name;
        $this->result_name = $result_name;
        $this->success = $success;
        $this->fetcher = new TestFetcher($this->base_url);
        parent::PHPUnit_TestCase();
    }

    function setUp()
    {
        list($this->input_url, $this->expected) = generateResult($this->base_url,
                                                                 $this->input_name,
                                                                 $this->id_name,
                                                                 $this->result_name,
                                                                 $this->success);
    }

    function runTest()
    {
        if ($this->expected === null) {
            $result = Auth_Yadis_Yadis::discover($this->input_url,
                                                     $this->fetcher);
            $this->assertTrue($result->isFailure());
        } else {
            $result = Auth_Yadis_Yadis::discover($this->input_url,
                                                     $this->fetcher);

            if ($result === null) {
                $this->fail("Discovery result was null");
                return;
            }

            $this->assertEquals($this->input_url, $result->request_uri);

            $msg = 'Identity URL mismatch: actual = %s, expected = %s';
            $msg = sprintf($msg, $result->normalized_uri, $this->expected->uri);
            $this->assertEquals($this->expected->uri, $result->normalized_uri, $msg);

            $msg = 'Content mismatch: actual = %s, expected = %s';
            $msg = sprintf($msg, $result->response_text, $this->expected->body);
            $this->assertEquals($this->expected->body, $result->response_text, $msg);

            $this->assertEquals($this->expected->xrds_uri, $result->xrds_uri);
            $this->assertEquals($this->expected->content_type, $result->content_type);
        }
    }

    function getName()
    {
        if ($this->input_url) {
            return $this->input_url;
        } else {
            return $this->input_name;
        }
    }
}

class Tests_Auth_Yadis_Discover_Yadis extends PHPUnit_TestSuite {

    function getName()
    {
        return "Tests_Auth_Yadis_Discover_Yadis";
    }

    function Tests_Auth_Yadis_Discover_Yadis()
    {
        global $testlist;

        foreach ($testlist as $test) {
            list($success, $input_name, $id_name, $result_name) = $test;
            $this->addTest(new _TestCase($input_name, $id_name, $result_name, $success));
        }
    }
}

?>