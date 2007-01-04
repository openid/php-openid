<?php

require_once 'PHPUnit.php';

require_once 'Auth/OpenID.php';
require_once 'Auth/OpenID/Discover.php';
require_once 'Services/Yadis/Manager.php';
require_once 'Services/Yadis/Misc.php';
require_once 'Services/Yadis/XRI.php';

/**
 * Tests for the core of the PHP Yadis library discovery logic.
 */

class _SimpleMockFetcher {
    function _SimpleMockFetcher($responses)
    {
        $this->responses = $responses;
    }

    function get($url)
    {
        $response = array_pop($this->responses);
        assert($response[1] == $url);
        return $response;
    }
}

class Tests_Services_Yadis_DiscoveryFailure extends PHPUnit_TestCase {

    function Tests_Services_Yadis_DiscoveryFailure($responses)
    {
        // Response is ($code, $url, $body).
        $this->cases = array(
                             array(null, 'http://network.error/', ''),
                             array(404, 'http://not.found/', ''),
                             array(400, 'http://bad.request/', ''),
                             array(500, 'http://server.error/', ''),
                             array(200, 'http://header.found/', 200,
                                   array('x-xrds-location' => 'http://xrds.missing/')),
                             array(404, 'http://xrds.missing/', ''));

        $this->url = $responses[0]->final_url;
        $this->responses = $responses;
        $this->fetcher = new _SimpleMockFetcher($this->responses);
    }

    function runTest()
    {
        foreach ($this->cases as $case) {
            list($status, $url, $body) = $case;
            $expected_status = $status;

            $result = Auth_OpenID_discover($this->url, $this->fetcher);
            list($id_url, $svclist, $http_response) = $result;

            $this->assertEquals($http_response->status, $expected_status);
        }
    }
}

### Tests for raising/catching exceptions from the fetcher through the
### discover function

class _ErrorRaisingFetcher {
    // Just raise an exception when fetch is called

    function _ErrorRaisingFetcher($thing_to_raise)
    {
        $this->thing_to_raise = $thing_to_raise;
    }

    function post($body = null)
    {
        __raiseError($this->thing_to_raise);
    }

    function get($url)
    {
        __raiseError($this->thing_to_raise);
    }
}

define('E_AUTH_OPENID_EXCEPTION', 'e_exception');
define('E_AUTH_OPENID_DIDFETCH', 'e_didfetch');
define('E_AUTH_OPENID_VALUE_ERROR', 'e_valueerror');
define('E_AUTH_OPENID_RUNTIME_ERROR', 'e_runtimeerror');
define('E_AUTH_OPENID_OI', 'e_oi');

class Tests_Auth_OpenID_Discover_FetchException extends PHPUnit_TestCase {
    // Make sure exceptions get passed through discover function from
    // fetcher.

    function Tests_Auth_OpenID_Discover_FetchException($exc)
    {
        $this->cases = array(E_AUTH_OPENID_EXCEPTION,
                             E_AUTH_OPENID_DIDFETCH,
                             E_AUTH_OPENID_VALUE_ERROR,
                             E_AUTH_OPENID_RUNTIME_ERROR,
                             E_AUTH_OPENID_OI);
    }

    function runTest()
    {
        foreach ($this->cases as $thing_to_raise) {
            $fetcher = ErrorRaisingFetcher($thing_to_raise);
            Auth_OpenID_discover('http://doesnt.matter/', $fetcher);
            $exc = __getError();

            if ($exc !== $thing_to_raise) {
                $this->fail('FetchException expected %s to be raised',
                            $thing_to_raise);
            }
        }
    }
}


// Tests for openid.consumer.discover.discover

class _DiscoveryMockFetcher {
    function _DiscoveryMockFetcher(&$documents)
    {
        $this->redirect = null;
        $this->documents = &$documents;
        $this->fetchlog = array();
    }

    function post($url, $body = null, $headers = null)
    {
        return $this->get($url, $headers, $body);
    }

    function get($url, $headers = null, $body = null)
    {
        $this->fetchlog[] = array($url, $body, $headers);

        if ($this->redirect) {
            $final_url = $this->redirect;
        } else {
            $final_url = $url;
        }

        if (array_key_exists($url, $this->documents)) {
            list($ctype, $body) = $this->documents[$url];
            $status = 200;
        } else {
            $status = 404;
            $ctype = 'text/plain';
            $body = '';
        }

        return new Services_Yadis_HTTPResponse($final_url, $status,
                                               array('content-type' => $ctype), $body);
    }
}

define('DISCOVERYBASE_ID_URL', "http://someuser.unittest/");

class _DiscoveryBase extends PHPUnit_TestCase {
    var $id_url = DISCOVERYBASE_ID_URL;
    var $documents = array();

    function setUp()
    {
        $this->fetcher = new _DiscoveryMockFetcher($this->documents);
    }
}

$__yadis_2entries = '<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS xmlns:xrds="xri://$xrds"
           xmlns="xri://$xrd*($v*2.0)"
           xmlns:openid="http://openid.net/xmlns/1.0"
           >
  <XRD>
    <CanonicalID>=!1000</CanonicalID>

    <Service priority="10">
      <Type>http://openid.net/signon/1.0</Type>
      <URI>http://www.myopenid.com/server</URI>
      <openid:Delegate>http://smoker.myopenid.com/</openid:Delegate>
    </Service>

    <Service priority="20">
      <Type>http://openid.net/signon/1.0</Type>
      <URI>http://www.livejournal.com/openid/server.bml</URI>
      <openid:Delegate>http://frank.livejournal.com/</openid:Delegate>
    </Service>

  </XRD>
</xrds:XRDS>
';

$__yadis_2entries_flipped_priority = '<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS xmlns:xrds="xri://$xrds"
           xmlns="xri://$xrd*($v*2.0)"
           xmlns:openid="http://openid.net/xmlns/1.0"
           >
  <XRD>

    <Service priority="20">
      <Type>http://openid.net/signon/1.0</Type>
      <URI>http://www.myopenid.com/server</URI>
      <openid:Delegate>http://smoker.myopenid.com/</openid:Delegate>
    </Service>

    <Service priority="10">
      <Type>http://openid.net/signon/1.0</Type>
      <URI>http://www.livejournal.com/openid/server.bml</URI>
      <openid:Delegate>http://frank.livejournal.com/</openid:Delegate>
    </Service>

  </XRD>
</xrds:XRDS>
';

$__yadis_another = '<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS xmlns:xrds="xri://$xrds"
           xmlns="xri://$xrd*($v*2.0)"
           xmlns:openid="http://openid.net/xmlns/1.0"
           >
  <XRD>

    <Service priority="10">
      <Type>http://openid.net/signon/1.0</Type>
      <URI>http://vroom.unittest/server</URI>
      <openid:Delegate>http://smoker.myopenid.com/</openid:Delegate>
    </Service>
  </XRD>
</xrds:XRDS>
';

$__yadis_0entries = '<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS xmlns:xrds="xri://$xrds"
           xmlns="xri://$xrd*($v*2.0)"
           xmlns:openid="http://openid.net/xmlns/1.0"
           >
  <XRD>
    <Service >
      <Type>http://is-not-openid.unittest/</Type>
      <URI>http://noffing.unittest./</URI>
    </Service>
  </XRD>
</xrds:XRDS>
';

$__yadis_no_delegate = '<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS xmlns:xrds="xri://$xrds"
           xmlns="xri://$xrd*($v*2.0)"
           >
  <XRD>
    <Service priority="10">
      <Type>http://openid.net/signon/1.0</Type>
      <URI>http://www.myopenid.com/server</URI>
    </Service>
  </XRD>
</xrds:XRDS>
';

$__openid_html = '
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html>
  <head>
    <title>Identity Page for Smoker</title>
<link rel="openid.server" href="http://www.myopenid.com/server" />
<link rel="openid.delegate" href="http://smoker.myopenid.com/" />
  </head><body><p>foo</p></body></html>
';

$__openid_html_no_delegate = '
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html>
  <head>
    <title>Identity Page for Smoker</title>
<link rel="openid.server" href="http://www.myopenid.com/server" />
  </head><body><p>foo</p></body></html>
';

$__openid_and_yadis_html = '
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html>
  <head>
    <title>Identity Page for Smoker</title>
<meta http-equiv="X-XRDS-Location" content="http://someuser.unittest/xrds" />
<link rel="openid.server" href="http://www.myopenid.com/server" />
<link rel="openid.delegate" href="http://smoker.myopenid.com/" />
  </head><body><p>foo</p></body></html>
';

class _MockFetcherForXRIProxy {

    function _MockFetcherForXRIProxy($documents)
    {
        $this->documents = $documents;
        $this->fetchlog = array();
    }

    function get($url, $headers=null)
    {
        return $this->fetch($url, $headers);
    }

    function post($url, $body)
    {
        return $this->fetch($url, $body);
    }

    function fetch($url, $body=null, $headers=null)
    {
        $this->fetchlog[] = array($url, $body, $headers);

        $u = parse_url($url);
        $proxy_host = $u['host'];
        $xri = $u['path'];
        $query = $u['query'];

        if ((!$headers) && (!$query)) {
            trigger_error('Error in mock XRI fetcher: no headers or query');
        }

        if (Services_Yadis_startswith($xri, '/')) {
            $xri = substr($xri, 1);
        }

        if (array_key_exists($xri, $this->documents)) {
            list($ctype, $body) = $this->documents[$xri];
            $status = 200;
        } else {
            $status = 404;
            $ctype = 'text/plain';
            $body = '';
        }

        return new Services_Yadis_HTTPResponse($url, $status,
                                               array('content-type' => $ctype),
                                               $body);
    }
}

class Tests_Auth_OpenID_DiscoverSession {
    function Tests_Auth_OpenID_DiscoverSession()
    {
        $this->data = array();
    }

    function set($name, $value)
    {
        $this->data[$name] = $value;
    }

    function get($name, $default=null)
    {
        if (array_key_exists($name, $this->data)) {
            return $this->data[$name];
        } else {
            return $default;
        }
    }

    function del($name)
    {
        unset($this->data[$name]);
    }
}

$__Tests_BOGUS_SERVICE = new Auth_OpenID_ServiceEndpoint();
$__Tests_BOGUS_SERVICE->identity_url = "=really.bogus.endpoint";

function __serviceCheck_discover_cb($url, $fetcher)
{
    global $__Tests_BOGUS_SERVICE;
    return array($__Tests_BOGUS_SERVICE);
}

class Tests_Auth_OpenID_Discover extends _DiscoveryBase {
    function _usedYadis($service)
    {
        $this->assertTrue($service->used_yadis,
                          "Expected to use Yadis");
    }

    function _notUsedYadis($service)
    {
        $this->assertFalse($service->used_yadis,
                           "Expected to use old-style discovery");
    }

    function test_404()
    {
        $result = Auth_OpenID_discover($this->id_url . '/404',
                                       $this->fetcher);

        list($id_url, $svclist, $http_response) = $result;

        $this->assertTrue($http_response->status == 404,
                          "Expected 404 status from /404 discovery");
    }

    function test_noYadis()
    {
        global $__openid_html;

        $this->documents[$this->id_url] = array('text/html', $__openid_html);

        list($id_url, $services, $http_response) =
            Auth_OpenID_discover($this->id_url,
                                 $this->fetcher);

        $this->assertEquals($this->id_url, $id_url);

        $this->assertEquals(count($services), 1,
                            "More than one service");

        $this->assertEquals($services[0]->server_url,
                            "http://www.myopenid.com/server");

        $this->assertEquals($services[0]->delegate,
                            "http://smoker.myopenid.com/");

        $this->assertEquals($services[0]->identity_url, $this->id_url);
        $this->_notUsedYadis($services[0]);
    }

    function test_managerServices()
    {
        global $__yadis_2entries_flipped_priority;

        $url = "http://bogus.xxx/";
        $sess = new Tests_Auth_OpenID_DiscoverSession();
        $m = new Services_Yadis_Discovery($sess, $url);

        $documents = array(
                           $url => array("application/xrds+xml",
                                         $__yadis_2entries_flipped_priority)
                           );

        $fetcher = new _DiscoveryMockFetcher($documents);

        $expected = array("http://frank.livejournal.com/",
                          "http://smoker.myopenid.com/");

        foreach ($expected as $openid) {
            $s = $m->getNextService('_Auth_OpenID_discoverServiceList',
                                    $fetcher);
            $this->assertEquals($s->delegate, $openid);
        }
    }

    function test_serviceCheck()
    {
        global $__Tests_BOGUS_SERVICE;

        $url = "http://bogus.xxx/";
        $sess =& new Tests_Auth_OpenID_DiscoverSession();
        $disco =& new Services_Yadis_Discovery($sess, $url);

        # Set an empty manager to be sure it gets blown away
        $manager =& new Services_Yadis_Manager($url, null, array(),
                                               $disco->getSessionKey());

        $loader =& new Services_Yadis_ManagerLoader();
        $disco->session->set($disco->session_key,
                             serialize($loader->toSession($manager)));

        $docs = array();
        $fetcher =& new _DiscoveryMockFetcher($docs);

        $result = $disco->getNextService('__serviceCheck_discover_cb', $fetcher);

        $newMan = $disco->getManager();

        $currentService = $newMan->_current;
        $this->assertEquals($currentService->identity_url,
                            $__Tests_BOGUS_SERVICE->identity_url);
    }

    function test_noOpenID()
    {
        $this->fetcher->documents = array(
                          $this->id_url => array('text/plain', "junk"));

        list($id_url, $services, $http) = Auth_OpenID_discover($this->id_url,
                                                               $this->fetcher);

        $this->assertEquals($this->id_url, $id_url);

        $this->assertFalse(count($services) > 0);
    }

    function test_yadis()
    {
        global $__yadis_2entries;

        $this->fetcher->documents = array(
                 DISCOVERYBASE_ID_URL => array('application/xrds+xml',
                                               $__yadis_2entries));

        list($id_url, $services, $http) = Auth_OpenID_discover($this->id_url,
                                                               $this->fetcher);

        $this->assertEquals($this->id_url, $id_url);

        $this->assertEquals(count($services), 2,
                            "Not 2 services");

        $this->assertEquals($services[0]->server_url,
                            "http://www.myopenid.com/server");

        $this->_usedYadis($services[0]);

        $this->assertEquals($services[1]->server_url,
                            "http://www.livejournal.com/openid/server.bml");

        $this->_usedYadis($services[1]);
    }

    function test_redirect()
    {
        global $__openid_html;

        $expected_final_url = "http://elsewhere.unittest/";

        $this->fetcher->redirect = $expected_final_url;
        $this->fetcher->documents = array(
                             $this->id_url => array('text/html', $__openid_html));

        list($id_url, $services, $http) = Auth_OpenID_discover($this->id_url,
                                                               $this->fetcher);

        $this->assertEquals($expected_final_url, $id_url);

        $this->assertEquals(count($services), 1,
                            "More than one service");

        $this->assertEquals($services[0]->server_url,
                            "http://www.myopenid.com/server");

        $this->assertEquals($services[0]->delegate,
                            "http://smoker.myopenid.com/");

        $this->assertEquals($services[0]->identity_url,
                            $expected_final_url);

        $this->_notUsedYadis($services[0]);
    }

    function test_emptyList()
    {
        global $__yadis_0entries;

        $this->fetcher->documents = array(
                                 $this->id_url =>
                                 array('application/xrds+xml', $__yadis_0entries));

        list($id_url, $services, $http) = Auth_OpenID_discover($this->id_url,
                                                               $this->fetcher);

        $this->assertEquals($this->id_url, $id_url);

        $this->assertTrue(count($services) == 0);
    }

    function test_emptyListWithLegacy()
    {
        global $__openid_and_yadis_html,
            $__yadis_0entries;

        $this->fetcher->documents = array(
            $this->id_url => array('text/html', $__openid_and_yadis_html),
            $this->id_url . 'xrds' => array('application/xrds+xml', $__yadis_0entries));

        list($id_url, $services, $http) = Auth_OpenID_discover($this->id_url,
                                                               $this->fetcher);

        $this->assertEquals($this->id_url, $id_url);

        $this->assertEquals(count($services), 1,
                            "Not one service");

        $this->assertEquals($services[0]->server_url,
                            "http://www.myopenid.com/server");

        $this->assertEquals($services[0]->identity_url, $this->id_url);

        $this->_notUsedYadis($services[0]);
    }

    function test_yadisNoDelegate()
    {
        global $__yadis_no_delegate;

        $this->fetcher->documents = array(
              $this->id_url => array('application/xrds+xml', $__yadis_no_delegate));

        list($id_url, $services, $http) = Auth_OpenID_discover($this->id_url,
                                                               $this->fetcher);

        $this->assertEquals($this->id_url, $id_url);

        $this->assertEquals(count($services), 1,
                            "Not 1 service");

        $this->assertEquals($services[0]->server_url,
                            "http://www.myopenid.com/server");

        $this->assertEquals($services[0]->delegate, null,
                            'Delegate should be null');

        $this->_usedYadis($services[0]);
    }

    function test_openidNoDelegate()
    {
        global $__openid_html_no_delegate;

        $this->fetcher->documents = array(
                      $this->id_url => array('text/html',
                                             $__openid_html_no_delegate));

        list($id_url, $services, $http) = Auth_OpenID_discover($this->id_url,
                                                               $this->fetcher);

        $this->assertEquals($this->id_url, $id_url);

        $this->assertEquals($services[0]->server_url,
                            "http://www.myopenid.com/server");

        $this->assertEquals($services[0]->identity_url, $this->id_url);

        $this->assertEquals($services[0]->delegate, null,
                            'Delegate should be null');

        $this->_notUsedYadis($services[0]);
    }

    function test_xriDiscovery()
    {
        global $__yadis_2entries;

        $documents = array(
                           '=smoker' => array('application/xrds+xml',
                                              $__yadis_2entries)
                           );

        $fetcher = new _MockFetcherForXRIProxy($documents);

        list($user_xri, $services) = _Auth_OpenID_discoverXRI('=smoker',
                                                              $fetcher);
        $this->assertTrue($services);

        $this->assertEquals($services[0]->server_url,
                            "http://www.myopenid.com/server");
        $this->assertEquals($services[1]->server_url,
                            "http://www.livejournal.com/openid/server.bml");
        $this->assertEquals($services[0]->canonicalID, Services_Yadis_XRI("=!1000"));
    }

    function test_useCanonicalID()
    {
      // When there is no delegate, the CanonicalID should be used
      // with XRI.

      $endpoint = new Auth_OpenID_ServiceEndpoint();
      $endpoint->identity_url = "=example";
      $endpoint->canonicalID = Services_Yadis_XRI("=!1000");
      $this->assertEquals($endpoint->getServerID(), Services_Yadis_XRI("=!1000"));
    }
}

?>