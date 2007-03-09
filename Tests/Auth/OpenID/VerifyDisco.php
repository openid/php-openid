<?php

require_once "PHPUnit.php";
require_once "Tests/Auth/OpenID/TestUtil.php";
require_once "Tests/Auth/OpenID/MemStore.php";

require_once "Auth/OpenID/Message.php";
require_once "Auth/OpenID/Consumer.php";

class Tests_Auth_OpenID_VerifyDisco extends OpenIDTestMixin {
    var $consumer_class = 'Auth_OpenID_GenericConsumer';

    function setUp()
    {
        $this->store = new Tests_Auth_OpenID_MemStore();
        $cl = $this->consumer_class;
        $this->consumer = new $cl($this->store);
        $this->return_to = "http://some.host/path";
        $this->endpoint = new Auth_OpenID_ServiceEndpoint();

        $this->server_id = "sirod";
        $this->server_url = "serlie";
        $this->consumer_id = "consu";

        $this->endpoint->claimed_id = $this->consumer_id;
        $this->endpoint->server_url = $this->server_url;
        $this->endpoint->local_id = $this->server_id;
        $this->endpoint->type_uris = array(Auth_OpenID_TYPE_1_1);
    }

    function failUnlessProtocolError($thing)
    {
        $this->assertTrue(Auth_OpenID::isFailure($thing));
    }

    function test_openID1NoLocalID()
    {
        $endpoint = new Auth_OpenID_ServiceEndpoint();
        $endpoint->claimed_id = 'bogus';

        $msg = Auth_OpenID_Message::fromOpenIDArgs(array());
        // 'Missing required field openid.identity'
        $this->failUnlessProtocolError($this->consumer->_verifyDiscoveryResults($msg, $endpoint));
    }

    function test_openID1NoEndpoint()
    {
        $msg = Auth_OpenID_Message::fromOpenIDArgs(array('identity' => 'snakes on a plane'));
        $this->failUnlessProtocolError($this->consumer->_verifyDiscoveryResults($msg));
    }

    function test_openID2NoOPEndpointArg()
    {
        $msg = Auth_OpenID_Message::fromOpenIDArgs(array('ns' => Auth_OpenID_OPENID2_NS));
        $this->failUnlessProtocolError($this->consumer->_verifyDiscoveryResults($msg, null));
    }

    function test_openID2LocalIDNoClaimed()
    {
        $msg = Auth_OpenID_Message::fromOpenIDArgs(array('ns' => Auth_OpenID_OPENID2_NS,
                                                         'op_endpoint' => 'Phone Home',
                                                         'identity' => 'Jose Lius Borges'));
        // 'openid.identity is present without',
        $this->failUnlessProtocolError($this->consumer->_verifyDiscoveryResults($msg));
    }

    function test_openID2NoLocalIDClaimed()
    {
        $msg = Auth_OpenID_Message::fromOpenIDArgs(array('ns' => Auth_OpenID_OPENID2_NS,
                                                         'op_endpoint' => 'Phone Home',
                                                         'claimed_id' => 'Manuel Noriega'));
        // 'openid.claimed_id is present without',
        $this->failUnlessProtocolError(
           $this->consumer->_verifyDiscoveryResults($msg));
    }

    function test_openID2NoIdentifiers()
    {
        $op_endpoint = 'Phone Home';
        $msg = Auth_OpenID_Message::fromOpenIDArgs(array('ns' => Auth_OpenID_OPENID2_NS,
                                                         'op_endpoint' => $op_endpoint));
        $result_endpoint = $this->consumer->_verifyDiscoveryResults($msg);
        $this->assertTrue($result_endpoint->isOPIdentifier());
        $this->assertEquals($op_endpoint, $result_endpoint->server_url);
        $this->assertEquals(null, $result_endpoint->claimed_id);
    }

    function test_openid2UsePreDiscovered()
    {
        $endpoint = new Auth_OpenID_ServiceEndpoint();
        $endpoint->local_id = 'my identity';
        $endpoint->claimed_id = 'i am sam';
        $endpoint->server_url = 'Phone Home';
        $endpoint->type_uris = array(Auth_OpenID_TYPE_2_0);

        $msg = Auth_OpenID_Message::fromOpenIDArgs(
                    array('ns' => Auth_OpenID_OPENID2_NS,
                          'identity' => $endpoint->local_id,
                          'claimed_id' => $endpoint->claimed_id,
                          'op_endpoint' => $endpoint->server_url));

        $result = $this->consumer->_verifyDiscoveryResults($msg, $endpoint);
        $this->assertTrue($result === $endpoint);
    }

    function test_openid2UsePreDiscoveredWrongType()
    {
        $endpoint = new Auth_OpenID_ServiceEndpoint();
        $endpoint->local_id = 'my identity';
        $endpoint->claimed_id = 'i am sam';
        $endpoint->server_url = 'Phone Home';
        $endpoint->type_uris = array(Auth_OpenID_TYPE_1_1);

        $msg = Auth_OpenID_Message::fromOpenIDArgs(
              array('ns' => Auth_OpenID_OPENID2_NS,
                    'identity' => $endpoint->local_id,
                    'claimed_id' => $endpoint->claimed_id,
                    'op_endpoint' => $endpoint->server_url));

        $this->failUnlessProtocolError(
           $this->consumer->_verifyDiscoveryResults($msg, $endpoint));
    }

    function test_openid1UsePreDiscovered()
    {
        $endpoint = new Auth_OpenID_ServiceEndpoint();
        $endpoint->local_id = 'my identity';
        $endpoint->claimed_id = 'i am sam';
        $endpoint->server_url = 'Phone Home';
        $endpoint->type_uris = array(Auth_OpenID_TYPE_1_1);

        $msg = Auth_OpenID_Message::fromOpenIDArgs(
            array('ns' => Auth_OpenID_OPENID1_NS,
                  'identity' => $endpoint->local_id));
        $result = $this->consumer->_verifyDiscoveryResults($msg, $endpoint);
        $this->assertTrue($result == $endpoint);
    }

    function test_openid1UsePreDiscoveredWrongType()
    {
        $endpoint = new Auth_OpenID_ServiceEndpoint();
        $endpoint->local_id = 'my identity';
        $endpoint->claimed_id = 'i am sam';
        $endpoint->server_url = 'Phone Home';
        $endpoint->type_uris = array(Auth_OpenID_TYPE_2_0);

        $msg = Auth_OpenID_Message::fromOpenIDArgs(
            array('ns' => Auth_OpenID_OPENID1_NS,
                  'identity' => $endpoint->local_id));
        $this->failUnlessProtocolError(
            $this->consumer->_verifyDiscoveryResults($msg, $endpoint));
    }
}

// XXX: test the implementation of _discoverAndVerify

class Tests_openID2NoEndpointDoesDisco_sentinel extends Auth_OpenID_GenericConsumer {
    var $sentinel = 'blah';

    function _discoverAndVerify($to_match)
    {
        return $this->sentinel;
    }
}

class Tests_openID2NoEndpointDoesDisco extends Tests_Auth_OpenID_VerifyDisco {
    var $consumer_class = 'Tests_openID2NoEndpointDoesDisco_sentinel';

    function test_openID2NoEndpointDoesDisco()
    {
        $op_endpoint = 'Phone Home';
        $sentinel = 'thing';
        $msg = Auth_OpenID_Message::fromOpenIDArgs(
            array('ns' => Auth_OpenID_OPENID2_NS,
                  'identity' => 'sour grapes',
                  'claimed_id' => 'monkeysoft',
                  'op_endpoint' => $op_endpoint));

        $result = $this->consumer->_verifyDiscoveryResults($msg);
        $this->assertEquals($this->consumer->sentinel, $result);
    }
}

class Tests_openID2MismatchedDoesDisco extends Tests_Auth_OpenID_VerifyDisco {
    var $consumer_class = 'Tests_openID2NoEndpointDoesDisco_sentinel';

    function test_openID2MismatchedDoesDisco()
    {
        $mismatched = new Auth_OpenID_ServiceEndpoint();
        $mismatched->identity = 'nothing special, but different';
        $mismatched->local_id = 'green cheese';

        $op_endpoint = 'Phone Home';

        $msg = Auth_OpenID_Message::fromOpenIDArgs(
            array('ns' => Auth_OpenID_OPENID2_NS,
                  'identity' => 'sour grapes',
                  'claimed_id' => 'monkeysoft',
                  'op_endpoint' => $op_endpoint));

        $result = $this->consumer->_verifyDiscoveryResults($msg, $mismatched);
        $this->assertEquals($this->consumer->sentinel, $result);
    }
}

class TestVerifyDiscoverySingle extends OpenIDTestMixin {
    var $consumer_class = 'Auth_OpenID_GenericConsumer';

    function setUp()
    {
        $this->store = new Tests_Auth_OpenID_MemStore();
        $cl = $this->consumer_class;
        $this->consumer = new $cl($this->store);
        $this->return_to = "http://some.host/path";
        $this->endpoint = new Auth_OpenID_ServiceEndpoint();

        $this->server_id = "sirod";
        $this->server_url = "serlie";
        $this->consumer_id = "consu";

        $this->endpoint->claimed_id = $this->consumer_id;
        $this->endpoint->server_url = $this->server_url;
        $this->endpoint->local_id = $this->server_id;
        $this->endpoint->type_uris = array(Auth_OpenID_TYPE_1_1);
    }

    function test_endpointWithoutLocalID()
    {
        // An endpoint like this with no local_id is generated as a
        // result of e.g. Yadis discovery with no LocalID tag.
        $endpoint = new Auth_OpenID_ServiceEndpoint();
        $endpoint->server_url = "http://localhost:8000/openidserver";
        $endpoint->claimed_id = "http://localhost:8000/id/id-jo";

        $to_match = new Auth_OpenID_ServiceEndpoint();
        $to_match->server_url = "http://localhost:8000/openidserver";
        $to_match->claimed_id = "http://localhost:8000/id/id-jo";
        $to_match->local_id = "http://localhost:8000/id/id-jo";

        $result = $this->consumer->_verifyDiscoverySingle($endpoint, $to_match);

        // result should always be None, raises exception on failure.
        $this->assertEquals($result, null);
    }
}

global $Tests_Auth_OpenID_VerifyDisco_other;
$Tests_Auth_OpenID_VerifyDisco_other = array(
                                             new Tests_openID2MismatchedDoesDisco(),
                                             new Tests_openID2NoEndpointDoesDisco()
                                             );

?>