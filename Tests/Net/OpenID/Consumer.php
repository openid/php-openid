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

require_once('Net/OpenID/CryptUtil.php');
require_once('Net/OpenID/DiffieHellman.php');
require_once('Net/OpenID/Store/FileStore.php');
require_once('Net/OpenID/OIDUtil.php');
require_once('Net/OpenID/KVForm.php');
require_once('Net/OpenID/Consumer/Consumer.php');

$_Net_OpenID_assocs = array(
                            array('another 20-byte key.', 'Snarky'),
                            array(str_repeat("\x00", 20), 'Zeros'),
                            );

$_Net_OpenID_filestore_base_dir = "/tmp";

function Net_OpenID_parse($qs)
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

function Net_OpenID_associate($qs, $assoc_secret, $assoc_handle)
{
    $query_data = Net_OpenID_parse($qs);

    assert((count($query_data) == 6) || (count($query_data) == 4));
    assert($query_data['openid.mode'] == 'associate');
    assert($query_data['openid.assoc_type'] == 'HMAC-SHA1');
    assert($query_data['openid.session_type'] == 'DH-SHA1');
    $d = Net_OpenID_DiffieHellman::fromBase64(
        Net_OpenID_array_get($query_data, 'openid.dh_modulus', null),
        Net_OpenID_array_get($query_data, 'openid.dh_gen', null));

    $composite = Net_OpenID_CryptUtil::base64ToLong(
        $query_data['openid.dh_consumer_public']);

    $enc_mac_key = Net_OpenID_CryptUtil::toBase64(
                      $d->xorSecret($composite, $assoc_secret));

    $reply_dict = array(
                        'assoc_type' => 'HMAC-SHA1',
                        'assoc_handle' => $assoc_handle,
                        'expires_in' => '600',
                        'session_type' => 'DH-SHA1',
                        'dh_server_public' =>
                           Net_OpenID_CryptUtil::longToBase64($d->public),
                        'enc_mac_key' => $enc_mac_key,
                        );

    return Net_OpenID_KVForm::arrayToKV($reply_dict);
}

class Net_OpenID_TestFetcher {
    function Net_OpenID_TestFetcher($user_url, $user_page,
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

    function post($url, $body)
    {
        if (strpos($body, 'openid.mode=associate') !== false) {
            $response = Net_OpenID_associate($body, $this->assoc_secret,
                                             $this->assoc_handle);
            $this->num_assocs++;
            return $this->response($url, $response);
        } else {
            return $this->response($url, null);
        }
    }
}

$_Net_OpenID_user_page_pat = "<html>
  <head>
    <title>A user page</title>
    %s
  </head>
  <body>
    blah blah
  </body>
</html>";

$_Net_OpenID_server_url = "http://server.example.com/";
$_Net_OpenID_consumer_url = "http://consumer.example.com/";

class Tests_Net_OpenID_Consumer extends PHPUnit_TestCase {

    function _run(&$consumer, $user_url, $mode, $delegate_url,
                  &$fetcher, &$store)
    {
        global $Net_OpenID_SUCCESS,
            $_Net_OpenID_consumer_url,
            $_Net_OpenID_server_url;

        list($status, $info) = $consumer->beginAuth($user_url);
        $this->assertEquals($status, $Net_OpenID_SUCCESS);

        $return_to = $_Net_OpenID_consumer_url;
        $trust_root = $_Net_OpenID_consumer_url;
        $redirect_url = $consumer->constructRedirect($info, $return_to,
                                                     $trust_root);

        $parsed = parse_url($redirect_url);
        $qs = $parsed['query'];
        $q = Net_OpenID_parse($qs);

        $this->assertEquals($q, array(
                                      'openid.mode' => $mode,
                                      'openid.identity' => $delegate_url,
                                      'openid.trust_root' => $trust_root,
                                      'openid.assoc_handle' =>
                                         $fetcher->assoc_handle,
                                      'openid.return_to' => $return_to
                                      ));

        $this->assertEquals(strpos($redirect_url, $_Net_OpenID_server_url),
                            0);

        $query = array(
                       'openid.mode'=> 'id_res',
                       'openid.return_to'=> $return_to,
                       'openid.identity'=> $delegate_url,
                       'openid.assoc_handle'=> $fetcher->assoc_handle,
                       );

        $assoc = $store->getAssociation($_Net_OpenID_server_url,
                                        $fetcher->assoc_handle);

        $assoc->addSignature(array('mode', 'return_to', 'identity'), $query);

        list($status, $info) = $consumer->completeAuth($info->token, $query);

        $this->assertEquals($status, $Net_OpenID_SUCCESS);
        $this->assertEquals($info, $user_url);
    }

    function _test_success($user_url, $delegate_url, $links, $immediate = false)
    {
        global $_Net_OpenID_filestore_base_dir,
            $_Net_OpenID_server_url,
            $_Net_OpenID_user_page_pat,
            $_Net_OpenID_assocs;

        $store = new Net_OpenID_FileStore(
           Net_OpenID_mkdtemp($_Net_OpenID_filestore_base_dir));

        if ($immediate) {
            $mode = 'checkid_immediate';
        } else {
            $mode = 'checkid_setup';
        }

        $user_page = sprintf($_Net_OpenID_user_page_pat, $links);
        $fetcher = new Net_OpenID_TestFetcher($user_url, $user_page,
                                              $_Net_OpenID_assocs[0][0],
                                              $_Net_OpenID_assocs[0][1]);

        $consumer = new Net_OpenID_Consumer($store, $fetcher, $immediate);

        $this->assertEquals($fetcher->num_assocs, 0);
        $this->_run($consumer, $user_url, $mode, $delegate_url,
                    $fetcher, $store);

        $this->assertEquals($fetcher->num_assocs, 1);

        // Test that doing it again uses the existing association
        $this->_run($consumer, $user_url, $mode, $delegate_url,
                    $fetcher, $store);

        $this->assertEquals($fetcher->num_assocs, 1);

        // Another association is created if we remove the existing one
        $store->removeAssociation($_Net_OpenID_server_url,
                                  $fetcher->assoc_handle);

        $this->_run($consumer, $user_url, $mode, $delegate_url,
                    $fetcher, $store);

        $this->assertEquals($fetcher->num_assocs, 2);

        // Test that doing it again uses the existing association
        $this->_run($consumer, $user_url, $mode, $delegate_url,
                    $fetcher, $store);

        $this->assertEquals($fetcher->num_assocs, 2);

        $store->destroy();
    }

    function test_success()
    {
        global $_Net_OpenID_server_url;

        $user_url = 'http://www.example.com/user.html';
        $links = sprintf('<link rel="openid.server" href="%s" />',
                         $_Net_OpenID_server_url);

        $delegate_url = 'http://consumer.example.com/user';
        $delegate_links = sprintf('<link rel="openid.server" href="%s" />'.
                                  '<link rel="openid.delegate" href="%s" />',
                                  $_Net_OpenID_server_url, $delegate_url);

        $this->_test_success($user_url, $user_url, $links);
        $this->_test_success($user_url, $user_url, $links, true);
        $this->_test_success($user_url, $delegate_url, $delegate_links);
        $this->_test_success($user_url, $delegate_url, $delegate_links, true);
    }

    function test_bad_fetch()
    {
        global $_Net_OpenID_filestore_base_dir,
            $Net_OpenID_HTTP_FAILURE;

        $store = new Net_OpenID_FileStore(
            Net_OpenID_mkdtemp($_Net_OpenID_filestore_base_dir));

        $fetcher = new Net_OpenID_TestFetcher(null, null, null, null);
        $consumer = new Net_OpenID_Consumer($store, $fetcher);
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
            $this->assertEquals($status, $Net_OpenID_HTTP_FAILURE);
            $this->assertEquals($info, $error_code);
        }

        $store->destroy();
    }

    function test_bad_parse()
    {
        global $_Net_OpenID_filestore_base_dir,
            $Net_OpenID_PARSE_ERROR;

        $store = new Net_OpenID_FileStore(
            Net_OpenID_mkdtemp($_Net_OpenID_filestore_base_dir));

        $user_url = 'http://user.example.com/';
        $cases = array(
                       '',
                       "http://not.in.a.link.tag/",
                       '<link rel="openid.server" href="not.in.html.or.head" />'
                       );

        foreach ($cases as $user_page) {
            $fetcher = new Net_OpenID_TestFetcher($user_url, $user_page,
                                                  null, null);
            $consumer = new Net_OpenID_Consumer($store, $fetcher);
            list($status, $info) = $consumer->beginAuth($user_url);
            $this->assertEquals($status, $Net_OpenID_PARSE_ERROR);
            $this->assertNull($info);
        }

        $store->destroy();
    }
}

?>