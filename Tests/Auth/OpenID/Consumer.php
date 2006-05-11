<?php

/**
 * Tests for the OpenID consumer.
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

require_once 'Auth/OpenID/CryptUtil.php';
require_once 'Auth/OpenID/HTTPFetcher.php';
require_once 'Auth/OpenID/DiffieHellman.php';
require_once 'Auth/OpenID/FileStore.php';
require_once 'Auth/OpenID/KVForm.php';
require_once 'Auth/OpenID/Consumer.php';
require_once 'Auth/OpenID/HTTPFetcher.php';
require_once 'Tests/Auth/OpenID/MemStore.php';
require_once 'PHPUnit.php';

class Auth_OpenID_TestConsumer extends Auth_OpenID_GenericConsumer {
    /**
     * Use a small (insecure) modulus for this test so that it runs quickly
     */
    function _createDiffieHellman()
    {
        return new Auth_OpenID_DiffieHellman('1235514290909');
    }
}

$_Auth_OpenID_assocs = array(
                            array('another 20-byte key.', 'Snarky'),
                            array(str_repeat("\x00", 20), 'Zeros'),
                            );

$_Auth_OpenID_filestore_base_dir = "/tmp";

function Auth_OpenID_parse($qs)
{
    $result = array();
    $parts = explode("&", $qs);
    foreach ($parts as $pair) {
        list($key, $value) = explode("=", $pair, 2);
        assert(!array_key_exists($key, $result));
        $result[$key] = urldecode($value);
    }
    return $result;
}

function Auth_OpenID_associate($qs, $assoc_secret, $assoc_handle)
{
    $query_data = Auth_OpenID_parse($qs);

    assert((count($query_data) == 6) || (count($query_data) == 4));
    assert($query_data['openid.mode'] == 'associate');
    assert($query_data['openid.assoc_type'] == 'HMAC-SHA1');
    assert($query_data['openid.session_type'] == 'DH-SHA1');

    $reply_dict = array(
        'assoc_type' => 'HMAC-SHA1',
        'assoc_handle' => $assoc_handle,
        'expires_in' => '600',
        );

    $dh_args = Auth_OpenID_DiffieHellman::
        serverAssociate($query_data, $assoc_secret);

    $reply_dict = array_merge($reply_dict, $dh_args);

    return Auth_OpenID_KVForm::fromArray($reply_dict);
}

class Auth_OpenID_TestFetcher extends Auth_OpenID_HTTPFetcher {
    function Auth_OpenID_TestFetcher($user_url, $user_page,
                                    $assoc_secret, $assoc_handle)
    {
        $this->get_responses = array($user_url =>
                                     new Auth_OpenID_HTTPResponse($user_url,
                                                                  200,
                                                                  array(),
                                                                  $user_page));
        $this->assoc_secret = $assoc_secret;
        $this->assoc_handle = $assoc_handle;
        $this->num_assocs = 0;
    }

    function response($url, $body)
    {
        if ($body === null) {
            return new Auth_OpenID_HTTPResponse($url, 404, array(), 'Not found');
        } else {
            return new Auth_OpenID_HTTPResponse($url, 200, array(), $body);
        }
    }

    function get($url)
    {
        if (array_key_exists($url, $this->get_responses)) {
            return $this->get_responses[$url];
        } else {
            return $this->response($url, null);
        }
    }

    function _checkAuth($url, $body)
    {
        $query_data = Auth_OpenID_parse($body);
        $expected = array(
                          'openid.mode' => 'check_authentication',
                          'openid.signed' => 'assoc_handle,sig,signed',
                          'openid.sig' => 'fake',
                          'openid.assoc_handle' => $this->assoc_handle,
                          );

        if ($query_data == $expected) {
            return new Auth_OpenID_HTTPResponse($url, 200, array(), "is_valid:true\n");
        } else {
            return new Auth_OpenID_HTTPResponse($url, 400, array(),
                                                "error:bad check_authentication query\n");
        }
    }

    function post($url, $body)
    {
        if (strpos($body, 'openid.mode=associate') !== false) {
            $response = Auth_OpenID_associate($body, $this->assoc_secret,
                                              $this->assoc_handle);
            $this->num_assocs++;
            return $this->response($url, $response);
        } elseif (strpos($body, 'openid.mode=check_authentication') !== false) {
            return $this->_checkAuth($url, $body);
        } else {
            return $this->response($url, null);
        }
    }
}

$_Auth_OpenID_user_page_pat = "<html>
  <head>
    <title>A user page</title>
    %s
  </head>
  <body>
    blah blah
  </body>
</html>";

$_Auth_OpenID_server_url = "http://server.example.com/";
$_Auth_OpenID_consumer_url = "http://consumer.example.com/";

class Tests_Auth_OpenID_Consumer extends PHPUnit_TestCase {

    function _run(&$consumer, $user_url, $mode, $delegate_url,
                  &$fetcher, &$store, $immediate)
    {
        global $_Auth_OpenID_consumer_url,
            $_Auth_OpenID_server_url;

        $endpoint = new Auth_OpenID_ServiceEndpoint();
        $endpoint->identity_url = $user_url;
        $endpoint->server_url = $_Auth_OpenID_server_url;
        $endpoint->delegate = $delegate_url;

        $result = $consumer->begin($endpoint);

        $return_to = $_Auth_OpenID_consumer_url;
        $trust_root = $_Auth_OpenID_consumer_url;
        $redirect_url = $result->redirectURL($trust_root, $return_to,
                                             $immediate);

        $parsed = parse_url($redirect_url);
        $qs = $parsed['query'];
        $q = Auth_OpenID_parse($qs);
        $new_return_to = $q['openid.return_to'];
        unset($q['openid.return_to']);

        $expected = array(
                          'openid.mode' => $mode,
                          'openid.identity' => $delegate_url,
                          'openid.trust_root' => $trust_root
                          );

        if ($consumer->_use_assocs) {
            $expected['openid.assoc_handle'] = $fetcher->assoc_handle;
        }

        $this->assertEquals($expected, $q);
        $this->assertEquals(0, strpos($redirect_url, $_Auth_OpenID_server_url));
        $this->assertEquals(0, strpos($new_return_to, $return_to));

        $query = array(
                       'nonce' => $result->return_to_args['nonce'],
                       'openid.mode'=> 'id_res',
                       'openid.return_to'=> $new_return_to,
                       'openid.identity'=> $delegate_url,
                       'openid.assoc_handle'=> $fetcher->assoc_handle,
                       );

        if ($consumer->_use_assocs) {
            $assoc = $store->getAssociation($_Auth_OpenID_server_url,
                                            $fetcher->assoc_handle);

            $assoc->addSignature(array('mode', 'return_to', 'identity'),
                                 $query);
        } else {
            $query['openid.signed'] =
                'assoc_handle,sig,signed';
            $query['openid.assoc_handle'] = $fetcher->assoc_handle;
            $query['openid.sig'] = 'fake';
        }

        $result = $consumer->complete($query, $result->token);

        $this->assertEquals($result->status, 'success');
        $this->assertEquals($result->identity_url, $user_url);
    }

    function _test_success($user_url, $delegate_url, $links, $immediate = false)
    {
        global $_Auth_OpenID_filestore_base_dir,
            $_Auth_OpenID_server_url,
            $_Auth_OpenID_user_page_pat,
            $_Auth_OpenID_assocs;

        $store = new Auth_OpenID_FileStore(
           Auth_OpenID_FileStore::_mkdtemp($_Auth_OpenID_filestore_base_dir));

        if ($immediate) {
            $mode = 'checkid_immediate';
        } else {
            $mode = 'checkid_setup';
        }

        $user_page = sprintf($_Auth_OpenID_user_page_pat, $links);
        $fetcher = new Auth_OpenID_TestFetcher($user_url, $user_page,
                                              $_Auth_OpenID_assocs[0][0],
                                              $_Auth_OpenID_assocs[0][1]);

        $consumer = new Auth_OpenID_TestConsumer($store);
        $consumer->fetcher =& $fetcher;

        $expected_num_assocs = 0;
        $this->assertEquals($expected_num_assocs, $fetcher->num_assocs);
        $this->_run($consumer, $user_url, $mode, $delegate_url,
                    $fetcher, $store, $immediate);

        if ($consumer->_use_assocs) {
            $expected_num_assocs += 1;
        }

        $this->assertEquals($expected_num_assocs, $fetcher->num_assocs);

        // Test that doing it again uses the existing association
        $this->_run($consumer, $user_url, $mode, $delegate_url,
                    $fetcher, $store, $immediate);

        $this->assertEquals($expected_num_assocs, $fetcher->num_assocs);

        // Another association is created if we remove the existing one
        $store->removeAssociation($_Auth_OpenID_server_url,
                                  $fetcher->assoc_handle);

        $this->_run($consumer, $user_url, $mode, $delegate_url,
                    $fetcher, $store, $immediate);

        if ($consumer->_use_assocs) {
            $expected_num_assocs += 1;
        }

        $this->assertEquals($expected_num_assocs, $fetcher->num_assocs);

        // Test that doing it again uses the existing association
        $this->_run($consumer, $user_url, $mode, $delegate_url,
                    $fetcher, $store, $immediate);

        $this->assertEquals($expected_num_assocs, $fetcher->num_assocs);

        $store->destroy();
    }

    function test_success()
    {
        global $_Auth_OpenID_server_url;

        $user_url = 'http://www.example.com/user.html';
        $links = sprintf('<link rel="openid.server" href="%s" />',
                         $_Auth_OpenID_server_url);

        $delegate_url = 'http://consumer.example.com/user';
        $delegate_links = sprintf('<link rel="openid.server" href="%s" />'.
                                  '<link rel="openid.delegate" href="%s" />',
                                  $_Auth_OpenID_server_url, $delegate_url);

        $this->_test_success($user_url, $user_url, $links);
        $this->_test_success($user_url, $user_url, $links, true);
        $this->_test_success($user_url, $delegate_url, $delegate_links);
        $this->_test_success($user_url, $delegate_url, $delegate_links, true);
    }
}

class _TestIdRes extends PHPUnit_TestCase {
    var $consumer_class = 'Auth_OpenID_GenericConsumer';

    function setUp()
    {
        $this->store = new Tests_Auth_OpenID_MemStore();
        $cl = $this->consumer_class;
        $this->consumer = new $cl($this->store);
        $this->return_to = "nonny";
        $this->server_id = "sirod";
        $this->server_url = "serlie";
        $this->consumer_id = "consu";
    }
}

class Tests_Auth_OpenID_Consumer_TestSetupNeeded extends _TestIdRes {
    function test_setupNeeded()
    {
        $setup_url = "http://unittest/setup-here";
        $query = array(
                       'openid.mode' => 'id_res',
                       'openid.user_setup_url' => $setup_url);
        $ret = $this->consumer->_doIdRes($query, $this->consumer_id,
                                         $this->server_id, $this->server_url);
        $this->assertEquals($ret->status, Auth_OpenID_SETUP_NEEDED);
        $this->assertEquals($ret->setup_url, $setup_url);
    }
}

define('E_CHECK_AUTH_HAPPENED', 'checkauth occurred');
define('E_MOCK_FETCHER_EXCEPTION', 'mock fetcher exception');
define('E_ASSERTION_ERROR', 'assertion error');

class _CheckAuthDetectingConsumer extends Auth_OpenID_GenericConsumer {
    function _checkAuth($query, $server_url)
    {
        __raiseError(E_CHECK_AUTH_HAPPENED);
    }
}

class Tests_Auth_OpenID_Consumer_CheckNonceTest extends _TestIdRes {
    function setUp()
    {
        parent::setUp();
        $this->nonce = "t3stn0nc3";
        $this->store->storeNonce($this->nonce);
    }

    function test_goodNonce()
    {
        $this->return_to = sprintf('http://rt.unittest/?nonce=%s',
                                   $this->nonce);
        $this->response = new Auth_OpenID_SuccessResponse($this->consumer_id,
                                   array('openid.return_to' => $this->return_to));

        $ret = $this->consumer->_checkNonce($this->response, $this->nonce);
        $this->assertEquals($ret->status, Auth_OpenID_SUCCESS);
        $this->assertEquals($ret->identity_url, $this->consumer_id);
    }

    function test_badNonce()
    {
        // remove the nonce from the store
        $this->store->useNonce($this->nonce);
        $this->return_to = sprintf('http://rt.unittest/?nonce=%s',
                                   $this->nonce);
        $this->response = new Auth_OpenID_SuccessResponse($this->consumer_id,
                                 array('openid.return_to' => $this->return_to));
        $ret = $this->consumer->_checkNonce($this->response, $this->nonce);
        $this->assertEquals($ret->status, Auth_OpenID_FAILURE);
        $this->assertEquals($ret->identity_url, $this->consumer_id);
        $this->assertTrue(strpos($ret->message, 'Nonce missing from store') === 0);
    }

    function test_tamperedNonce()
    {
        $this->return_to = sprintf('http://rt.unittest/?nonce=HACKED-%s',
                                   $this->nonce);
        $this->response = new Auth_OpenID_SuccessResponse($this->consumer_id,
                                  array('openid.return_to' => $this->return_to));
        $ret = $this->consumer->_checkNonce($this->response, $this->nonce);
        $this->assertEquals($ret->status, Auth_OpenID_FAILURE);
        $this->assertEquals($ret->identity_url, $this->consumer_id);
        $this->assertTrue(strpos($ret->message, 'Nonce mismatch') === 0);
    }

    function test_missingNonce()
    {
        // no nonce parameter on the return_to
        $this->response = new Auth_OpenID_SuccessResponse($this->consumer_id,
                                     array('openid.return_to' => $this->return_to));
        $ret = $this->consumer->_checkNonce($this->response, $this->nonce);
        $this->assertEquals($ret->status, Auth_OpenID_FAILURE);
        $this->assertEquals($ret->identity_url, $this->consumer_id);
        $this->assertTrue(strpos($ret->message,
                                 'Nonce missing from return_to') === 0);
    }
}

class Tests_Auth_OpenID_Consumer_TestCheckAuthTriggered extends _TestIdRes {
    var $consumer_class = '_CheckAuthDetectingConsumer';

    function _doIdRes($query)
    {
        return $this->consumer->_doIdRes($query,
                                         $this->consumer_id,
                                         $this->server_id,
                                         $this->server_url);
    }

    function test_checkAuthTriggered()
    {
        $query = array('openid.return_to' => $this->return_to,
                       'openid.identity' => $this->server_id,
                       'openid.assoc_handle' =>'not_found');

        $result = $this->_doIdRes($query);
        $error = __getError();

        if ($error === null) {
            $this->fail('_checkAuth did not happen.');
        }
    }

    function test_checkAuthTriggeredWithAssoc()
    {
        // Store an association for this server that does not match
        // the handle that is in the query
        $issued = time();
        $lifetime = 1000;
        $assoc = new Auth_OpenID_Association(
                      'handle', 'secret', $issued, $lifetime, 'HMAC-SHA1');
        $this->store->storeAssociation($this->server_url, $assoc);

        $query = array(
            'openid.return_to' => $this->return_to,
            'openid.identity' => $this->server_id,
            'openid.assoc_handle' =>'not_found');

        $result = $this->_doIdRes($query);
        $error = __getError();

        if ($error === null) {
            $this->fail('_checkAuth did not happen.');
        }
    }

    function test_expiredAssoc()
    {
        // Store an expired association for the server with the handle
        // that is in the query
        $issued = time() - 10;
        $lifetime = 0;
        $handle = 'handle';
        $assoc = new Auth_OpenID_Association(
                        $handle, 'secret', $issued, $lifetime, 'HMAC-SHA1');
        $this->assertTrue($assoc->getExpiresIn() <= 0);
        $this->store->storeAssociation($this->server_url, $assoc);

        $query = array(
            'openid.return_to' => $this->return_to,
            'openid.identity' => $this->server_id,
            'openid.assoc_handle' => $handle);

        $info = $this->_doIdRes($query);
        $this->assertEquals('failure', $info->status);
        $this->assertEquals($this->consumer_id, $info->identity_url);

        $this->assertTrue(strpos($info->message, 'expired') !== false);
    }

    function test_newerAssoc()
    {
        // Store an expired association for the server with the handle
        // that is in the query
        $lifetime = 1000;

        $good_issued = time() - 10;
        $good_handle = 'handle';
        $good_assoc = new Auth_OpenID_Association(
                $good_handle, 'secret', $good_issued, $lifetime, 'HMAC-SHA1');
        $this->store->storeAssociation($this->server_url, $good_assoc);

        $bad_issued = time() - 5;
        $bad_handle = 'handle2';
        $bad_assoc = new Auth_OpenID_Association(
                  $bad_handle, 'secret', $bad_issued, $lifetime, 'HMAC-SHA1');
        $this->store->storeAssociation($this->server_url, $bad_assoc);

        $query = array(
            'openid.return_to' => $this->return_to,
            'openid.identity' => $this->server_id,
            'openid.assoc_handle' => $good_handle);

        $good_assoc->addSignature(array('return_to', 'identity'), $query);
        $info = $this->_doIdRes($query);
        $this->assertEquals($info->status, 'success');
        $this->assertEquals($this->consumer_id, $info->identity_url);
    }
}

class _MockFetcher {
    function _MockFetcher($response = null)
    {
        // response is (code, url, body)
        $this->response = $response;
        $this->fetches = array();
    }

    function post($url, $body)
    {
        $this->fetches[] = array($url, $body, array());
        return $this->response;
    }

    function get($url)
    {
        $this->fetches[] = array($url, null, array());
        return $this->response;
    }
}

class _ExceptionRaisingMockFetcher {
    function get($url)
    {
        __raiseError(E_MOCK_FETCHER_EXCEPTION);
    }

    function post($url, $body)
    {
        __raiseError(E_MOCK_FETCHER_EXCEPTION);
    }
}

class _BadArgCheckingConsumer extends Auth_OpenID_GenericConsumer {
    function _makeKVPost($args, $tmp)
    {
        if ($args != array(
            'openid.mode' => 'check_authentication',
            'openid.signed' => 'foo')) {
            __raiseError(E_ASSERTION_ERROR);
        }
        return null;
    }
}

class Tests_Auth_OpenID_Consumer_TestCheckAuth extends _TestIdRes {
    function setUp()
    {
        $this->store = new Tests_Auth_OpenID_MemStore();
        $this->consumer = new Auth_OpenID_GenericConsumer($this->store);
        $this->fetcher = new _MockFetcher();
        $this->consumer->fetcher =& $this->fetcher;
    }

    function test_checkauth_error()
    {
        global $_Auth_OpenID_server_url;
        $this->fetcher->response = new Auth_OpenID_HTTPResponse("http://some_url",
                                                                404,
                                                                array(),
                                                                "blah:blah\n");
        $query = array('openid.signed' => 'stuff, things');
        $r = $this->consumer->_checkAuth($query, $_Auth_OpenID_server_url);
        if ($r !== false) {
            $this->fail("Expected _checkAuth result to be false");
        }
    }

    function test_bad_args()
    {
        $query = array('openid.signed' => 'foo',
                       'closid.foo' => 'something');

        $consumer = new _BadArgCheckingConsumer($this->store);
        $consumer->_checkAuth($query, 'does://not.matter');
        $this->assertEquals(__getError(), E_ASSERTION_ERROR);
    }
}

class Tests_Auth_OpenID_Consumer_TestFetchAssoc extends PHPUnit_TestCase {
    function setUp()
    {
        $this->store = new Tests_Auth_OpenID_MemStore();
        $this->fetcher = new _MockFetcher();
        $this->consumer = new Auth_OpenID_GenericConsumer($this->store);
        $this->consumer->fetcher =& $this->fetcher;
    }

    function test_kvpost_error()
    {
        $this->fetcher->response = new Auth_OpenID_HTTPResponse("http://some_url",
                                                                404,
                                                                array(),
                                                                "blah:blah\n");
        $r = $this->consumer->_makeKVPost(array('openid.mode' => 'associate'),
                                          "http://server_url");
        if ($r !== null) {
            $this->fail("Expected _makeKVPost result to be null");
        }
    }

    function test_error_exception()
    {
        $this->consumer->fetcher = new _ExceptionRaisingMockFetcher();

        $this->consumer->_makeKVPost(array('openid.mode' => 'associate'),
                                     "http://server_url");

        if (__getError() !== E_MOCK_FETCHER_EXCEPTION) {
            $this->fail("Expected ExceptionRaisingMockFetcher to " .
                        "raise E_MOCK_FETCHER_EXCEPTION");
        }

        // exception fetching returns no association
        $this->assertEquals(@$this->consumer->_getAssociation('some://url'), null);

        $this->consumer->_checkAuth(array('openid.signed' => ''),
                                    'some://url');

        if (__getError() !== E_MOCK_FETCHER_EXCEPTION) {
            $this->fail("Expected ExceptionRaisingMockFetcher to " .
                        "raise E_MOCK_FETCHER_EXCEPTION (_checkAuth)");
        }
    }
}

// Add other test cases to be run.
$Tests_Auth_OpenID_Consumer_other = array(
                                          new Tests_Auth_OpenID_Consumer_TestSetupNeeded(),
                                          new Tests_Auth_OpenID_Consumer_TestCheckAuth(),
                                          new Tests_Auth_OpenID_Consumer_TestCheckAuthTriggered(),
                                          new Tests_Auth_OpenID_Consumer_TestFetchAssoc(),
                                          new Tests_Auth_OpenID_Consumer_CheckNonceTest()
                                          );

?>