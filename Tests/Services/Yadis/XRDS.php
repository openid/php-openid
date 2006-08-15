<?php

/**
 * XRDS-parsing tests for the Yadis library.
 */

require_once 'PHPUnit.php';
require_once 'Services/Yadis/XRDS.php';
require_once 'Tests/Services/Yadis/TestUtil.php';

class Tests_Services_Yadis_XRDS extends PHPUnit_TestCase {

    function test_good()
    {
        $xml = Tests_Services_Yadis_readdata("brian.xrds");
        $xrds = Services_Yadis_XRDS::parseXRDS($xml);

        $this->assertTrue($xrds !== null);

        if ($xrds) {
            $this->assertEquals(count($xrds->services()), 1);
        } else {
            $this->fail("Could not test XRDS service list because the ".
                        "XRDS object is null");
        }
    }

    function test_good_multi()
    {
        $xml = Tests_Services_Yadis_readdata("brian.multi.xrds");
        $xrds = Services_Yadis_XRDS::parseXRDS($xml);
        $this->assertTrue($xrds !== null);
        $this->assertEquals(count($xrds->services()), 1);
        $s = $xrds->services();
        $s = $s[0];

        $types = $s->getTypes();

        $this->assertTrue(count($types) == 1);
        $this->assertEquals('http://openid.net/signon/1.0',
                            $types[0]);
    }

    function test_good_uri_multi()
    {
        $xml = Tests_Services_Yadis_readdata("brian.multi_uri.xrds");
        $xrds = Services_Yadis_XRDS::parseXRDS($xml);
        $this->assertTrue($xrds !== null);
        $this->assertEquals(1, count($xrds->services()));
    }

    function test_uri_sorting()
    {
        $xml = Tests_Services_Yadis_readdata("uri_priority.xrds");
        $xrds = Services_Yadis_XRDS::parseXRDS($xml);
        $services = $xrds->services();
        $uris = $services[0]->getURIs();

        $expected_uris = array(
                               "http://zero.priority/",
                               "http://one.priority/",
                               "http://no.priority/"
                               );

        $this->assertEquals($uris, $expected_uris);
    }

    function test_bad()
    {
        $this->assertTrue(Services_Yadis_XRDS::parseXRDS(null) === null);
        $this->assertTrue(Services_Yadis_XRDS::parseXRDS(5) === null);
        $this->assertTrue(Services_Yadis_XRDS::parseXRDS('') === null);
        $this->assertTrue(Services_Yadis_XRDS::parseXRDS('<html></html>') ===
                          null);
        $this->assertTrue(Services_Yadis_XRDS::parseXRDS("\x00") === null);
    }

    function test_services_filters()
    {
        // First, just be sure that service objects do the right
        // thing.
        $xml = Tests_Services_Yadis_readdata("brian_priority.xrds");
        $xrds = Services_Yadis_XRDS::parseXRDS($xml,
                                               array('openid' =>
                                                     'http://openid.net/xmlns/1.0'));
        $this->assertTrue($xrds !== null);

        // Get list of service objects.
        $services = $xrds->services();
        $this->assertEquals(count($services), 2, "first service count");

        // Query the two service objecs.
        $s1 = $services[0];
        $this->assertEquals($s1->getPriority(), 1, "first priority check");
        $types = $s1->getTypes();
        $this->assertEquals(count($types), 1, "first type check");

        $s2 = $services[1];
        $this->assertEquals($s2->getPriority(), 2, "second priority check");
        $types = $s2->getTypes();
        $this->assertEquals(count($types), 1, "second type check");

        function _DelegateFilter(&$service)
            {
                if ($service->getElements('openid:Delegate')) {
                    return true;
                }
                return false;
            }

        // Make sure that a filter which matches both DOES match both.
        $this->assertEquals(count(
                              $xrds->services(array("_DelegateFilter"))), 2,
                            "_DelegateFilter check");

        // This filter should match all services in the document.
        function _HasTypeAndURI(&$service)
            {
                if ($service->getTypes() &&
                    $service->getURIs()) {
                    return true;
                }
                return false;
            }

        // This filter should only match one.
        function _URIMatchesSchtuff(&$service)
            {
                $uris = $service->getURIs();

                foreach ($uris as $uri) {
                    if (preg_match("|schtuff|", $uri)) {
                        return true;
                    }
                }
                return false;
            }

        // This filter should only match one.
        function _URIMatchesMyOpenID(&$service)
            {
                $uris = $service->getURIs();

                foreach ($uris as $uri) {
                    if (preg_match("|myopenid|", $uri)) {
                        return true;
                    }
                }
                return false;
            }

        // Make sure a pair of filters in ALL mode only match one service.
        $this->assertEquals(count(
                              $xrds->services(array("_HasTypeAndURI",
                                                    "_URIMatchesSchtuff"),
                                              SERVICES_YADIS_MATCH_ALL)), 1,
                            "_HasTypeAndURI / _URIMatchesSchtuff check");

        // Make sure a pair of filters in ALL mode only match one service.
        $this->assertEquals(count(
                              $xrds->services(array("_HasTypeAndURI",
                                                    "_URIMatchesMyOpenID"),
                                              SERVICES_YADIS_MATCH_ALL)), 1,
                            "_HasTypeAndURI / _URIMatchesMyOpenID check");

        // Make sure a pair of filters in ANY mode matches both services.
        $this->assertEquals(count(
                              $xrds->services(array("_URIMatchesMyOpenID",
                                                    "_URIMatchesSchtuff"))), 2,
                            "_URIMatchesMyOpenID / _URIMatchesSchtuff check");

        // Make sure the order of the services returned (when using
        // filters) is correct.
        $s = $xrds->services(array("_URIMatchesMyOpenID",
                                   "_URIMatchesSchtuff"));

        $this->assertTrue($s[0]->getPriority() === 1, "s[0] priority check");
        $this->assertTrue($s[1]->getPriority() === 2, "s[1] priority check");

        // Make sure a bad filter mode gets us a null service list.
        $this->assertTrue($xrds->services(array("_URIMatchesMyOpenID",
                                                "_URIMatchesSchtuff"),
                                          "bogus") === null,
                          "bogus filter check");
    }
}

?>