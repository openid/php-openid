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
require_once 'Auth/OpenID/DiffieHellman.php';
require_once 'Auth/OpenID/Store/FileStore.php';
require_once 'Auth/OpenID/OIDUtil.php';
require_once 'Auth/OpenID/KVForm.php';
require_once 'Auth/OpenID/Consumer/Consumer.php';

class Auth_OpenID_TestConsumer extends Auth_OpenID_Consumer {
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

    return Auth_OpenID_KVForm::arrayToKV($reply_dict);
}

class Auth_OpenID_TestFetcher {
    function Auth_OpenID_TestFetcher($user_url, $user_page,
                                    $assoc_secret, $assoc_handle)
    {
        $this->get_responses = array($user_url => array(200,
                                                        $user_url,
                                                        $user_page));
        $this->assoc_secret = $assoc_secret;
        $this->assoc_handle = $assoc_handle;
        $this->num_assocs = 0;
    }

    function response($url, $body)
    {
        if ($body === null) {
            return array(404, $url, 'Not found');
        } else {
            return array(200, $url, $body);
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
            return array(200, $url, "is_valid:true\n");
        } else {
            return array(400, $url, "error:bad check_authentication query\n");
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
                  &$fetcher, &$store)
    {
        global $Auth_OpenID_SUCCESS,
            $_Auth_OpenID_consumer_url,
            $_Auth_OpenID_server_url;

        list($status, $info) = $consumer->beginAuth($user_url);
        $this->assertEquals($Auth_OpenID_SUCCESS, $status);

        $return_to = $_Auth_OpenID_consumer_url;
        $trust_root = $_Auth_OpenID_consumer_url;
        $redirect_url = $consumer->constructRedirect($info, $return_to,
                                                     $trust_root);

        $parsed = parse_url($redirect_url);
        $qs = $parsed['query'];
        $q = Auth_OpenID_parse($qs);

        $expected = array(
                          'openid.mode' => $mode,
                          'openid.identity' => $delegate_url,
                          'openid.trust_root' => $trust_root,
                          'openid.return_to' => $return_to
                          );

        if ($consumer->_use_assocs) {
            $expected['openid.assoc_handle'] = $fetcher->assoc_handle;
        }

        $this->assertEquals($expected, $q);

        $this->assertEquals(0, strpos($redirect_url, $_Auth_OpenID_server_url));

        $query = array(
                       'openid.mode'=> 'id_res',
                       'openid.return_to'=> $return_to,
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

        list($status, $info) = $consumer->completeAuth($info->token, $query);

        $this->assertEquals($Auth_OpenID_SUCCESS, $status);
        $this->assertEquals($info, $user_url);
    }

    function _test_success($user_url, $delegate_url, $links, $immediate = false)
    {
        global $_Auth_OpenID_filestore_base_dir,
            $_Auth_OpenID_server_url,
            $_Auth_OpenID_user_page_pat,
            $_Auth_OpenID_assocs;

        $store = new Auth_OpenID_FileStore(
           Auth_OpenID_mkdtemp($_Auth_OpenID_filestore_base_dir));

        if ($immediate) {
            $mode = 'checkid_immediate';
        } else {
            $mode = 'checkid_setup';
        }

        $user_page = sprintf($_Auth_OpenID_user_page_pat, $links);
        $fetcher = new Auth_OpenID_TestFetcher($user_url, $user_page,
                                              $_Auth_OpenID_assocs[0][0],
                                              $_Auth_OpenID_assocs[0][1]);

        $consumer = new Auth_OpenID_TestConsumer($store, &$fetcher, $immediate);

        $expected_num_assocs = 0;
        $this->assertEquals($expected_num_assocs, $fetcher->num_assocs);
        $this->_run($consumer, $user_url, $mode, $delegate_url,
                    $fetcher, $store);

        if ($consumer->_use_assocs) {
            $expected_num_assocs += 1;
        }

        $this->assertEquals($expected_num_assocs, $fetcher->num_assocs);

        // Test that doing it again uses the existing association
        $this->_run($consumer, $user_url, $mode, $delegate_url,
                    $fetcher, $store);

        $this->assertEquals($expected_num_assocs, $fetcher->num_assocs);

        // Another association is created if we remove the existing one
        $store->removeAssociation($_Auth_OpenID_server_url,
                                  $fetcher->assoc_handle);

        $this->_run($consumer, $user_url, $mode, $delegate_url,
                    $fetcher, $store);

        if ($consumer->_use_assocs) {
            $expected_num_assocs += 1;
        }

        $this->assertEquals($expected_num_assocs, $fetcher->num_assocs);

        // Test that doing it again uses the existing association
        $this->_run($consumer, $user_url, $mode, $delegate_url,
                    $fetcher, $store);

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

    function test_bad_fetch()
    {
        global $_Auth_OpenID_filestore_base_dir,
            $Auth_OpenID_HTTP_FAILURE;

        $store = new Auth_OpenID_FileStore(
            Auth_OpenID_mkdtemp($_Auth_OpenID_filestore_base_dir));

        $fetcher = new Auth_OpenID_TestFetcher(null, null, null, null);
        $consumer = new Auth_OpenID_TestConsumer($store, &$fetcher);
        $cases = array(
                       array(null, 'http://network.error/'),
                       array(404, 'http://not.found/'),
                       array(400, 'http://bad.request/'),
                       array(500, 'http://server.error/')
                       );

        foreach ($cases as $case) {
            list($error_code, $url) = $case;
            $fetcher->get_responses[$url] = array($error_code, $url, null);
            list($status, $info) = $consumer->beginAuth($url);
            $this->assertEquals($status, $Auth_OpenID_HTTP_FAILURE);
            $this->assertEquals($info, $error_code);
        }

        $store->destroy();
    }

    function test_bad_parse()
    {
        global $_Auth_OpenID_filestore_base_dir,
            $Auth_OpenID_PARSE_ERROR;

        $store = new Auth_OpenID_FileStore(
            Auth_OpenID_mkdtemp($_Auth_OpenID_filestore_base_dir));

        $user_url = 'http://user.example.com/';
        $cases = array(
                       '',
                       "http://not.in.a.link.tag/",
                       '<link rel="openid.server" href="not.in.html.or.head" />'
                       );

        foreach ($cases as $user_page) {
            $fetcher = new Auth_OpenID_TestFetcher($user_url, $user_page,
                                                  null, null);
            $consumer = new Auth_OpenID_TestConsumer($store, $fetcher);
            list($status, $info) = $consumer->beginAuth($user_url);
            $this->assertEquals($status, $Auth_OpenID_PARSE_ERROR);
            $this->assertNull($info);
        }

        $store->destroy();
    }
}

?>