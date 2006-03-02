<?php

/**
 * This module contains an implementation of an OpenID server as
 * Auth_OpenID_Server.
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

/**
 * Required imports
 */
require_once "Auth/OpenID.php";
require_once "Auth/OpenID/Association.php";
require_once "Auth/OpenID/CryptUtil.php";
require_once "Auth/OpenID/DiffieHellman.php";
require_once "Auth/OpenID/KVForm.php";
require_once "Auth/OpenID/TrustRoot.php";
require_once "Auth/OpenID/ServerRequest.php";

/**
 * An object that implements the OpenID protocol for a single URL.
 *
 * Use this object by calling getOpenIDResponse when you get any
 * request for the server URL.
 *
 * @package OpenID
 */
class Auth_OpenID_Server {

    /**
     * A store implementing the interface in Auth/OpenID/Interface.php
     */
    var $store;

    /**
     * The URL of the server that this instance represents.
     */
    var $server_url;

    /**
     * The server URL with a namespace indicating that this
     * association is a shared association.
     *
     * @access private
     */
    var $_normal_key;

    /**
     * The server URL with a namespace indicating that this
     * association is a private (dumb-mode) association.
     *
     * @access private
     */
    var $_dumb_key;

    /**
     * How long an association should be valid for (in seconds)
     */
    var $association_lifetime = 1209600; // 14 days, in seconds

    /**
     * Constructor.
     *
     * @param string $server_url The URL of the OpenID server
     *
     * @param mixed $store The association store for this
     *     instance. See {@link Auth_OpenID_OpenIDStore}.
     */
    function Auth_OpenID_Server($server_url, $store)
    {
        $this->server_url = $server_url;
        $this->store =& $store;

        $this->_normal_key = $server_url . '|normal';
        $this->_dumb_key = $server_url . '|dumb';
    }

    /**
     * This is the initial entry point for a server URL.
     *
     * @param mixed $is_authorized: the name of a callback to use for
     * determining if a given identity URL should be authorized. It
     * will be called with the identity URL and the trust_root for
     * this request.
     *
     * @param string $method The HTTP method of the current
     * request. If omitted, $_SERVER['HTTP_METHOD'] will be used.
     *
     * @param array $args The arguments parsed from the request. If
     * omitted, the arguments in the environment will be used.
     *
     * @return array $array A pair of elements in which the first is a
     * status code and the meaning of the second depends on the
     * status. See the status codes defined in this file for
     * information about each response.
     */
    function getOpenIDResponse($is_authorized=false, $method=null, $args=null)
    {
        if (!isset($method)) {
            $method = $_SERVER['REQUEST_METHOD'];
        }

        switch ($method) {

        case 'GET':
            // Convert anything that starts with openid_ to openid.
            if ($args === null) {
                $args = Auth_OpenID::fixArgs($_GET);
            }
            $request = new Auth_OpenID_ServerRequest($this->server_url, $args);
            return $request->retry(&$this, $is_authorized);

        case 'POST':
            if ($args === null) {
                $args = Auth_OpenID::fixArgs($_POST);
            }
            $mode = $args['openid.mode'];
            switch ($mode) {

            case 'associate':
                return $this->associate($args);

            case 'check_authentication':
                return $this->checkAuthentication($args);

            default:
                $err = "Invalid openid.mode ($mode) for a POST request";
                return $this->postError($err);
            }

        default:
            $err = "HTTP method $method is not part of OpenID";
            return array(Auth_OpenID_LOCAL_ERROR, $err);
        }
    }

    /**
     * @access private
     *
     * @param object $request The Auth_OpenID_ServerRequest
     * object representing this request.
     *
     * @param bool $authorized Whether the user making this request is
     * capable of approving this authorization request.
     */
    function getAuthResponse(&$request, $authorized)
    {
        $identity = $request->getIdentityURL();
        if (!isset($identity)) {
            return $this->getError($request, 'No identity specified');
        }

        list($status, $info) = $this->_checkTrustRoot(&$request);
        if (!$status) {
            return $this->getError($request, $info);
        } else {
            $return_to = $info;
        }

        if (!$authorized) {
            return $this->_getAuthNotAuthorized(&$request, $return_to);
        } else {
            return $this->_getAuthAuthorized(&$request, $return_to);
        }
    }

    /**
     * Return whether the return_to URL matches the trust_root for
     * this request.
     *
     * @access private
     */
    function _checkTrustRoot(&$request)
    {
        $return_to = $request->getReturnTo();
        if (!isset($return_to)) {
            return array(false, 'No return_to URL specified');
        }

        $trust_root = $request->getTrustRoot();
        if (isset($trust_root) &&
            !Auth_OpenID_TrustRoot::match($trust_root, $return_to)) {
            return array(false, 'Trust root does not match');
        }
        return array(true, $return_to);
    }

    /**
     * @access private
     */
    function _getAuthNotAuthorized(&$request, $return_to)
    {
        $mode = $request->getMode();
        switch ($mode) {
        case 'checkid_immediate':
            // Build a URL that is just the URL that came here
            // with the mode changed from checkid_immediate to
            // checkid_setup.
            $args = $request->args;
            $args['openid.mode'] = 'checkid_setup';
            $setup_url = Auth_OpenID::appendArgs($this->server_url, $args);

            // Return to the consumer, instructing it that the user
            // needs to do something in order to verify his identity.
            $rargs = array(
                           'openid.mode' => 'id_res',
                           'openid.user_setup_url' => $setup_url
                           );

            $redir_url = Auth_OpenID::appendArgs($return_to, $rargs);
            return array(Auth_OpenID_REDIRECT, $redir_url);

        case 'checkid_setup':
            // Return to the application indicating that the user
            // needs to authenticate.
            return array(Auth_OpenID_DO_AUTH, &$request);

        default:
            $err = sprintf('invalid openid.mode (%s) for GET requests', $mode);
            return $this->getError($request, $err);
        }
    }

    /**
     * @access private
     */
    function _getAuthAuthorized(&$request, $return_to)
    {
        $mode = $request->getMode();
        switch ($mode) {
        case 'checkid_immediate':
        case 'checkid_setup':
            break;
        default:
            $err = sprintf('invalid openid.mode (%s) for GET requests', $mode);
            return $this->getError($request, $err);
        }

        $reply = array('openid.mode' => 'id_res',
                       'openid.return_to' => $return_to,
                       'openid.identity' => $request->getIdentityURL()
                       );

        $assoc = null;
        $assoc_handle = @$request->args['openid.assoc_handle'];
        if (isset($assoc_handle)) {
            $key = $this->_normal_key;
            $assoc = $this->store->getAssociation($key, $assoc_handle);

            // fall back to dumb mode if assoc_handle not found,
            // and send the consumer an invalidate_handle message
            if (!isset($assoc) || $assoc->getExpiresIn() <= 0) {
                $assoc = null;
                $this->store->removeAssociation($key, $assoc_handle);
                $reply['openid.invalidate_handle'] = $assoc_handle;
            }
        }

        // Use dumb mode if there is no association.
        if ($assoc === null) {
            $assoc = $this->createAssociation('HMAC-SHA1');
            $this->store->storeAssociation($this->_dumb_key, $assoc);
        }

        $reply['openid.assoc_handle'] = $assoc->handle;
        $signed_fields = array('mode', 'identity', 'return_to');
        $assoc->addSignature($signed_fields, &$reply);
        $redir_url = Auth_OpenID::appendArgs($return_to, $reply);
        return array(Auth_OpenID_REDIRECT, $redir_url);
    }

    /**
     * Perform an openid.mode=associate query
     *
     * @access private
     */
    function associate($query)
    {
        $reply = array();

        $assoc_type = @$query['openid.assoc_type'];
        if (!isset($assoc_type)) {
            $assoc_type = 'HMAC-SHA1';
        }

        $assoc = $this->createAssociation($assoc_type);
        if (!isset($assoc)) {
            $fmt = 'unable to create an association for type %s';
            return $this->postError(sprinft($fmt, $assoc_type));
        }

        $this->store->storeAssociation($this->_normal_key, $assoc);

        if (isset($assoc_type)) {
            $reply['assoc_type'] = $assoc_type;
        }
        $reply['assoc_handle'] = $assoc->handle;
        $reply['expires_in'] = strval($assoc->getExpiresIn());

        if (defined('Auth_OpenID_NO_MATH_SUPPORT')) {
            $session_type = null;
        } else {
            $session_type = @$query['openid.session_type'];
        }

        switch ($session_type) {
        case 'DH-SHA1':
            $sess_reply = Auth_OpenID_DiffieHellman::
                serverAssociate($query, $assoc->secret);
            break;
        case null:
            $sess_reply = array('mac_key' => base64_encode($assoc->secret));
            break;
        default:
            $sess_reply = false;
        }

        if ($sess_reply === false) {
            $msg = "Association session (type $session_type) failed";
            return $this->postError($msg);
        }

        $reply = array_merge($reply, $sess_reply);
        $reply_kv = Auth_OpenID_KVForm::fromArray($reply);
        return array(Auth_OpenID_REMOTE_OK, $reply_kv);
    }

    /**
     * Perform an openid.mode=check_authentication request
     *
     * @access private
     */
    function checkAuthentication($args)
    {
        $handle = $args['openid.assoc_handle'];
        if (!isset($handle)) {
            return $this->postError('Missing openid.assoc_handle');
        }

        $store =& $this->store;
        $assoc = $store->getAssociation($this->_dumb_key, $handle);
        $reply = array('is_valid' => 'false');
        if ($assoc !== null && $assoc->getExpiresIn() > 0) {
            $signed = $args['openid.signed'];
            if (!isset($signed)) {
                return $this->postError('Missing openid.signed');
            }

            $sig = $args['openid.sig'];
            if (!isset($sig)) {
                return $this->postError('Missing openid.sig');
            }

            $to_verify = $args;
            $to_verify['openid.mode'] = 'id_res';
            $fields = explode(',', trim($signed));
            $tv_sig = $assoc->signDict($fields, $to_verify);

            if ($tv_sig == $sig) {
                $normal_key = $this->_normal_key;
                $store->removeAssociation($normal_key, $assoc->handle);
                $reply['is_valid'] = 'true';

                $inv_handle = @$args['openid.invalidate_handle'];
                if (isset($inv_handle)) {
                    $assoc = $store->getAssociation($normal_key, $inv_handle);
                    if (!isset($assoc)) {
                        $reply['invalidate_handle'] = $inv_handle;
                    }
                }
            }
        } elseif ($assoc !== null) {
            $store->removeAssociation($this->_dumb_key, $assoc_handle);
        }

        $kv = Auth_OpenID_KVForm::fromArray($reply);
        return array(Auth_OpenID_REMOTE_OK, $kv);
    }

    /**
     * Create a new association and store it
     *
     * @access private
     */
    function createAssociation($assoc_type)
    {
        if ($assoc_type == 'HMAC-SHA1') {
            $secret = Auth_OpenID_CryptUtil::getBytes(20);
        } else {
            // XXX: log
            return false;
        }

        $uniq = base64_encode(Auth_OpenID_CryptUtil::getBytes(4));
        $handle = sprintf('{%s}{%x}{%s}', $assoc_type, time(), $uniq);

        $ltime = $this->association_lifetime;
        $assoc = Auth_OpenID_Association::
            fromExpiresIn($ltime, $handle, $secret, $assoc_type);

        return $assoc;
    }

    /**
     * Return an error response for GET requests
     *
     * @access private
     */
    function getError($request, $msg)
    {
        $args = $request->args;
        $return_to = @$args['openid.return_to'];
        if (isset($return_to)) {
            $err = array(
                         'openid.mode' => 'error',
                         'openid.error' => $msg
                         );
            $redir_url = Auth_OpenID::appendArgs($return_to, $err);
            return array(Auth_OpenID_REDIRECT, $redir_url);
        } else {
            foreach (array_keys($args) as $k) {
                if (preg_match('/^openid\./', $k)) {
                    return array(Auth_OpenID_LOCAL_ERROR, $msg);
                }
            }

            return array(Auth_OpenID_DO_ABOUT, null);
        }
    }

    /**
     * Return an error response for POST requests
     *
     * @access private
     */
    function postError($msg)
    {
        $kv = Auth_OpenID_KVForm::fromArray(array('error' => $msg));
        return array(Auth_OpenID_REMOTE_ERROR, $kv);
    }
}

?>