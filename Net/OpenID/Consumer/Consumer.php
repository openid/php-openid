<?php

/**
 * This module documents the main interface with the OpenID consumer
 * libary. The only part of the library which has to be used and isn't
 * documented in full here is the store required to create an
 * OpenIDConsumer instance. More on the abstract store type and
 * concrete implementations of it that are provided in the
 * documentation for the constructor of the OpenIDConsumer class.
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

require_once("Net/OpenID/CryptUtil.php");
require_once("Net/OpenID/KVForm.php");
require_once("Net/OpenID/OIDUtil.php");
require_once("Net/OpenID/Association.php");
require_once("Net/OpenID/DiffieHellman.php");
require_once("Net/OpenID/Consumer/Parse.php");
require_once("Net/OpenID/Consumer/Fetchers.php");

$Net_OpenID_SUCCESS = 'success';
$Net_OpenID_FAILURE = 'failure';
$Net_OpenID_SETUP_NEEDED = 'setup needed';
$Net_OpenID_HTTP_FAILURE = 'http failure';
$Net_OpenID_PARSE_ERROR = 'parse error';

$_Net_OpenID_NONCE_CHRS = $_Net_OpenID_letters . $_Net_OpenID_digits;
$_Net_OpenID_TOKEN_LIFETIME = 60 * 5; // five minutes
$_Net_OpenID_NONCE_LEN = 8;

class Net_OpenID_Consumer {

    function Net_OpenID_Consumer($store, $fetcher = null, $immediate = false)
    {
        $this->store = $store;

        if ($fetcher === null) {
            $this->fetcher = _getHTTPFetcher();
        } else {
            $this->fetcher = $fetcher;
        }

        if ($immediate) {
            $this->mode = 'checkid_immediate';
        } else {
            $this->mode = 'checkid_setup';
        }

        $this->immediate = $immediate;
    }

    function beginAuth($user_url)
    {
        global $Net_OpenID_SUCCESS;

        list($status, $info) = $this->_findIdentityInfo($user_url);
        if ($status != $Net_OpenID_SUCCESS) {
            return array($status, $info);
        }

        list($consumer_id, $server_id, $server_url) = $info;
        return $this->_gotIdentityInfo($consumer_id, $server_id, $server_url);
    }

    function constructRedirect($auth_request, $return_to, $trust_root)
    {
        $assoc = $this->_getAssociation($auth_request->server_url,
                                        $replace = 1);
        // Because _getAssociation is asynchronous if the association is
        // not already in the store.
        return $this->_constructRedirect($assoc, $auth_request,
                                         $return_to, $trust_root);
    }

    function completeAuth($token, $query)
    {
        global $Net_OpenID_SUCCESS, $Net_OpenID_FAILURE;

        $mode = Net_OpenID_array_get($query, 'openid.mode', '');

        if ($mode == 'cancel') {
            return array($Net_OpenID_SUCCESS, null);
        } else if ($mode == 'error') {

            $error = Net_OpenID_array_get($query, 'openid.error', null);

            if ($error !== null) {
                Net_OpenID_log($error);
            }
            return array($Net_OpenID_FAILURE, null);
        } else if ($mode == 'id_res') {
            return $this->_doIdRes($token, $query);
        } else {
            return array($Net_OpenID_FAILURE, null);
        }
    }

    function _gotIdentityInfo($consumer_id, $server_id, $server_url)
    {
        global $Net_OpenID_SUCCESS, $_Net_OpenID_NONCE_CHRS;

        $nonce = Net_OpenID_CryptUtil::randomString($this->NONCE_LEN,
                                                    $_Net_OpenID_NONCE_CHRS);

        $token = $this->_genToken($nonce, $consumer_id,
                                  $server_id, $server_url);
        return array($Net_OpenID_SUCCESS,
                     Net_OpenID_AuthRequest($token, $server_id,
                                            $server_url, $nonce));
    }

    function _constructRedirect($assoc, $auth_req, $return_to, $trust_root)
    {
        $redir_args = array(
                            'openid.identity' => $auth_req->server_id,
                            'openid.return_to' => $return_to,
                            'openid.trust_root' => $trust_root,
                            'openid.mode' => $this->mode,
                            );

        if ($assoc !==  null) {
            redir_args['openid.assoc_handle'] = $assoc->handle;
        }

        $this->store->storeNonce($auth_req->nonce);
        return strval(Net_OpenID_appendArgs($auth_req->server_url,
                                            $redir_args));
    }

    function _doIdRes($token, $query)
    {
        global $Net_OpenID_FAILURE, $Net_OpenID_SETUP_NEEDED;

        $ret = $this->_splitToken($token);
        if ($ret === null) {
            return array($Net_OpenID_FAILURE, null);
        }

        list($nonce, $consumer_id, $server_id, $server_url) = $ret;

        $return_to = Net_OpenID_array_get($query, 'openid.return_to', null);
        $server_id2 = Net_OpenID_array_get($query, 'openid.identity', null);
        $assoc_handle = Net_OpenID_array_get($query,
                                             'openid.assoc_handle', null);

        if (($return_to === null) ||
            ($server_id === null) ||
            ($assoc_handle === null)) {
            return array($Net_OpenID_FAILURE, $consumer_id);
        }

        if ($server_id != $server_id2) {
            return array($Net_OpenID_FAILURE, $consumer_id);
        }

        $user_setup_url = Net_OpenID_array_get($query,
                                               'openid.user_setup_url', null);

        if ($user_setup_url !== null) {
            return array($Net_OpenID_SETUP_NEEDED, $user_setup_url);
        }

        $assoc = $this->store->getAssociation($server_url);

        if (($assoc === null) ||
            ($assoc->handle != $assoc_handle) ||
            ($assoc->expiresIn <= 0)) {
            // It's not an association we know about.  Dumb mode is
            // our only possible path for recovery.
            return array($this->_checkAuth($nonce, $query, $server_url),
                         $consumer_id);
        }

        // Check the signature
        $sig = Net_OpenID_array_get($query, 'openid.sig', null);
        $signed = Net_OpenID_array_get($query, 'openid.signed', null);
        if (($sig === null) ||
            ($signed === null)) {
            return array($Net_OpenID_FAILURE, $consumer_id);
        }

        $signed_list = explode(",", $signed);
        $v_sig = $assoc->signDict($signed_list, $query);

        if ($v_sig != $sig) {
            return array($Net_OpenID_FAILURE, $consumer_id);
        }

        if (!$this->store->useNonce($nonce)) {
            return array($Net_OpenID_FAILURE, $consumer_id);
        }

        return array($Net_OpenID_SUCCESS, $consumer_id);
    }

    function _checkAuth($nonce, $query, $server_url)
    {
        global $Net_OpenID_FAILURE, $Net_OpenID_SUCCESS;

        // XXX: send only those arguments that were signed?
        $signed = Net_OpenID_array_get($query, 'openid.signed', null);
        if ($signed === null) {
            return $Net_OpenID_FAILURE;
        }

        $whitelist = array('assoc_handle', 'sig',
                           'signed', 'invalidate_handle');

        $signed = array_merge(explode(",", $signed), $whitelist);

        $check_args = array();

        foreach ($query as $key => $value) {
            if (in_array(substr($key, 7), $signed)) {
                $check_args[$key] = $value;
            }
        }

        $check_args['openid.mode'] = 'check_authentication';
        $post_data = Net_OpenID_http_build_query($check_args);

        $ret = $this->fetcher->post($server_url, $post_data);
        if ($ret === null) {
            return $Net_OpenID_FAILURE;
        }

        $results = Net_OpenID_KVForm::kvToArray($ret[2]);
        $is_valid = Net_OpenID_array_get($results, 'is_valid', 'false');

        if ($is_valid == 'true') {
            $invalidate_handle = Net_OpenID_array_get($results,
                                                      'invalidate_handle',
                                                      null);
            if ($invalidate_handle !== null) {
                $this->store->removeAssociation($server_url,
                                                $invalidate_handle);
            }

            if (!$this->store->useNonce($nonce)) {
                return $Net_OpenID_FAILURE;
            }

            return $Net_OpenID_SUCCESS;
        }

        $error = Net_OpenID_array_get($results, 'error', null);
        if ($error !== null) {
            Net_OpenID_log(sprintf("Error message from server during " .
                                   "check_authentication: %s", error));
        }

        return $Net_OpenID_FAILURE;
    }

    function _getAssociation($server_url, $replace = false)
    {
        if ($this->store->isDumb()) {
            return null;
        }

        $assoc = $this->store->getAssociation($server_url);

        if (($assoc === null) ||
            ($replace && ($assoc->expiresIn < $this->TOKEN_LIFETIME))) {
            $dh = new Net_OpenID_DiffieHellman();
            $body = $this->_createAssociateRequest($dh);
            $assoc = $this->_fetchAssociation($dh, $server_url, $body);
        }

        return $assoc;
    }

    function _genToken($nonce, $consumer_id, $server_id, $server_url)
    {
        $timestamp = strval(time());
        $elements = array($timestamp, $nonce,
                          $consumer_id, $server_id, $server_url);

        $joined = implode("\x00", $elements);
        $sig = Net_OpenID_CryptUtil::hmacSha1($this->store->getAuthKey(),
                                              $joined);

        return Net_OpenID_toBase64($sig . $joined);
    }

    function _splitToken($token)
    {
        $token = Net_OpenID_fromBase64($token);
        if (strlen($token) < 20) {
            return null;
        }

        $sig = $joined = substr($token, 0, 20);
        if (Net_OpenID_CryptUtil::hmacSha1(
              $this->store->getAuthKey(), $joined) != $sig) {
            return null;
        }

        $split = explode("\x00", $joined);
        if (count($split) != 5) {
            return null;
        }

        $ts = intval($split[0]);
        if ($ts == 0) {
            return null;
        }

        if ($ts + $this->TOKEN_LIFETIME < time()) {
            return null;
        }

        return array_slice($split, 1);
    }

    function _findIdentityInfo($identity_url)
    {
        global $Net_OpenID_HTTP_FAILURE;

        $url = Net_OpenID_normalizeUrl($identity_url);
        $ret = $this->fetcher->get($url);
        if ($ret === null) {
            return array($Net_OpenID_HTTP_FAILURE, null);
        }

        list($http_code, $consumer_id, $data) = $ret;
        if ($http_code != 200) {
            return array($Net_OpenID_HTTP_FAILURE, $http_code);
        }

        // This method is split in two this way to allow for
        // asynchronous implementations of _findIdentityInfo.
        return $this->_parseIdentityInfo($data, $consumer_id);
    }

    function _parseIdentityInfo($data, $consumer_id)
    {
        global $Net_OpenID_PARSE_ERROR, $Net_OpenID_SUCCESS;

        $link_attrs = Net_OpenID_parseLinkAttrs($data);
        $server = Net_OpenID_findFirstHref($link_attrs, 'openid.server');
        $delegate = Net_OpenID_findFirstHref($link_attrs, 'openid.delegate');

        if ($server === null) {
            return array($Net_OpenID_PARSE_ERROR, null);
        }

        if ($delegate !== null) {
            $server_id = $delegate;
        } else {
            $server_id = $consumer_id;
        }

        $urls = array($consumer_id, $server_id, $server);

        $normalized = array();

        foreach ($urls as $url) {
            $normalized[] = Net_OpenID_normalizeUrl($url);
        }

        return array($Net_OpenID_SUCCESS, $normalized);
    }

    function _createAssociateRequest($dh, $args = null)
    {
        global $_Net_OpenID_DEFAULT_MOD, $_Net_OpenID_DEFAULT_GEN;

        if ($args === null) {
            $args = array();
        }

        $cpub = Net_OpenID_CryptUtil::longToBase64($dh->public);

        $args = array_merge($args, array(
                                         'openid.mode' =>  'associate',
                                         'openid.assoc_type' => 'HMAC-SHA1',
                                         'openid.session_type' => 'DH-SHA1',
                                         'openid.dh_consumer_public' => $cpub
                                         ));

        if (($dh->modulus != $_Net_OpenID_DEFAULT_MOD) ||
            ($dh->generator != $_Net_OpenID_DEFAULT_GEN)) {
            $args = array_merge($args,
                     array(
                           'openid.dh_modulus' =>
                           Net_OpenID_CryptUtil::longToBase64($dh->modulus),
                           'openid.dh_gen' =>
                           Net_OpenID_CryptUtil::longToBase64($dh->generator)
                           ));
        }

        return Net_OpenID_http_build_query($args);
    }

    function _fetchAssociation($dh, $server_url, $body)
    {
        $ret = $this->fetcher->post($server_url, $body);
        if ($ret === null) {
            $fmt = 'Getting association: failed to fetch URL: %s';
            Net_OpenID_log(sprintf($fmt, $server_url));
            return null;
        }

        list($http_code, $url, $data) = $ret;
        $results = Net_OpenID_KVForm::kvToArray($data);
        if ($http_code == 400) {
            $server_error = Net_OpenID_array_get($results, 'error',
                                                 '<no message from server>');

            $fmt = 'Getting association: error returned from server %s: %s';
            Net_OpenID_log(sprintf($fmt, $server_url, $server_error));
            return null;
        } else if ($http_code != 200) {
            $fmt = 'Getting association: bad status code from server %s: %s';
            Net_OpenID_log(sprintf($fmt, $server_url, $http_code));
            return null;
        }

        $results = Net_OpenID_KVForm::kvToArray($data);

        return $this->_parseAssociation($results, $dh, $server_url);
    }

    function _parseAssociation($results, $dh, $server_url)
    {
        $required_keys = array('assoc_type', 'assoc_handle',
                               'mac_key', 'dh_server_public',
                               'enc_mac_key');

        foreach ($required_keys as $key) {
            if (!array_key_exists($key, $results)) {
                Net_OpenID_log(sprintf("Getting association: missing key in ".
                                       "response from %s: %s",
                                       $server_url, $key),
                               E_USER_WARNING);
                return null;
            }
        }

        $assoc_type = $results['assoc_type'];
        if ($assoc_type != 'HMAC-SHA1') {
            $fmt = 'Unsupported assoc_type returned from server %s: %s';
            Net_OpenID_log(sprintf($fmt, $server_url, $assoc_type));
            return null;
        }

        $assoc_handle = $results['assoc_handle'];
        $expires_in = intval(Net_OpenID_array_get($results, 'expires_in', '0'));

        $session_type = Net_OpenID_array_get($results, 'session_type', null);
        if ($session_type === null) {
            $secret = Net_OpenID_fromBase64($results['mac_key']);
        } else {
            $fmt = 'Unsupported session_type returned from server %s: %s';
            if ($session_type != 'DH-SHA1') {
                Net_OpenID_log(sprintf($fmt, $server_url, $session_type));
                return null;
            }

            $spub = Net_OpenID_CryptUtil::base64ToLong(
                         $results['dh_server_public']);

            $enc_mac_key = Net_OpenID_CryptUtil::fromBase64(
                         $results['enc_mac_key']);

            $secret = $dh->xorSecret($spub, $enc_mac_key);
        }

        $assoc = Net_OpenID_Association::fromExpiresIn($expires_in,
                                                       $assoc_handle,
                                                       $secret,
                                                       $assoc_type);

        $this->store->storeAssociation($server_url, $assoc);
        return $assoc;
    }
}

class Net_OpenID_AuthRequest {
    function Net_OpenID_AuthRequest($token, $server_id, $server_url, $nonce)
    {
        $this->token = $token;
        $this->server_id = $server_id;
        $this->server_url = $server_url;
        $this->nonce = $nonce;
    }
}

?>