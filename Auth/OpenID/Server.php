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
require_once "Auth/OpenID/Association.php";
require_once "Auth/OpenID/CryptUtil.php";
require_once "Auth/OpenID/DiffieHellman.php";
require_once "Auth/OpenID/KVForm.php";
require_once "Auth/OpenID/Util.php";
require_once "Auth/OpenID/TrustRoot.php";

/**
 * Status code returned when the only option is to show an error page,
 * since we do not have enough information to redirect back to the
 * consumer. The associated value is an error message that should be
 * displayed on an HTML error page.
 */
define('Auth_OpenID_LOCAL_ERROR', 'local_error');

/**
 * Status code returned when there is an error to return in key-value
 * form to the consumer. The caller should return a 400 Bad Request
 * response with content-type text/plain and the value as the body.
 */
define('Auth_OpenID_REMOTE_ERROR', 'remote_error');

/**
 * Status code returned when there is a key-value form OK response to
 * the consumer. The value associated with this code is the
 * response. The caller should return a 200 OK response with
 * content-type text/plain and the value as the body.
 */
define('Auth_OpenID_REMOTE_OK', 'remote_ok');

/**
 * Status code returned when there is a redirect back to the
 * consumer. The value is the URL to redirect back to. The caller
 * should return a 302 Found redirect with a Location: header
 * containing the URL.
 */
define('Auth_OpenID_REDIRECT', 'redirect');

/**
 * Status code returned when the caller needs to authenticate the
 * user. The associated value is a Auth_OpenID_AuthorizationInfo
 * object that can be used to complete the authentication. If the user
 * has taken some authentication action, use the retry() method of the
 * Auth_OpenID_AuthorizationInfo object to complete the request.
 */
define('Auth_OpenID_DO_AUTH', 'do_auth');

/**
 * Status code returned when there were no OpenID arguments
 * passed. This code indicates that the caller should return a 200 OK
 * response and display an HTML page that says that this is an OpenID
 * server endpoint.
 */
define('Auth_OpenID_DO_ABOUT', 'do_about');

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
     * A store implementing the interface in Auth/OpenID/Store/Interface.php
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
     *     instance. See Auth_OpenID_OpenIDStore
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
                $args = Auth_OpenID_fixArgs($_GET);
            }
            $auth_info =
                new Auth_OpenID_AuthorizationInfo($this->server_url, $args);
            return $auth_info->retry(&$this, $is_authorized);

        case 'POST':
            if ($args === null) {
                $args = Auth_OpenID_fixArgs($_POST);
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
     * @param object $auth_info The Auth_OpenID_AuthorizationInfo
     * object representing this request.
     *
     * @param bool $authorized Whether the user making this request is
     * capable of approving this authorization request.
     */
    function getAuthResponse(&$auth_info, $authorized)
    {
        $identity = $auth_info->getIdentityURL();
        if (!isset($identity)) {
            return $this->getError($auth_info->args, 'No identity specified');
        }

        list($status, $info) = $this->_checkTrustRoot(&$auth_info);
        if (!$status) {
            return $this->getError($auth_info->args, $info);
        } else {
            $return_to = $info;
        }

        if (!$authorized) {
            return $this->_getAuthNotAuthorized(&$auth_info, $return_to);
        } else {
            return $this->_getAuthAuthorized(&$auth_info, $return_to);
        }
    }

    /**
     * Return whether the return_to URL matches the trust_root for
     * this request.
     *
     * @access private
     */
    function _checkTrustRoot(&$auth_info)
    {
        $return_to = $auth_info->getReturnTo();
        if (!isset($return_to)) {
            return array(false, 'No return_to URL specified');
        }

        $trust_root = $auth_info->getTrustRoot();
        if (isset($trust_root) &&
            !Auth_OpenID_matchTrustRoot($trust_root, $return_to)) {
            return array(false, 'Trust root does not match');
        }
        return array(true, $return_to);
    }

    /**
     * @access private
     */
    function _getAuthNotAuthorized(&$auth_info, $return_to)
    {
        $mode = $auth_info->getMode();
        switch ($mode) {
        case 'checkid_immediate':
            // Build a URL that is just the URL that came here
            // with the mode changed from checkid_immediate to
            // checkid_setup.
            $args = $auth_info->args;
            $args['openid.mode'] = 'checkid_setup';
            $setup_url = Auth_OpenID_appendArgs($this->server_url, $args);

            // Return to the consumer, instructing it that the user
            // needs to do something in order to verify his identity.
            $rargs = array(
                           'openid.mode' => 'id_res',
                           'openid.user_setup_url' => $setup_url
                           );

            $redir_url = Auth_OpenID_appendArgs($return_to, $rargs);
            return array(Auth_OpenID_REDIRECT, $redir_url);

        case 'checkid_setup':
            // Return to the application indicating that the user
            // needs to authenticate.
            return array(Auth_OpenID_DO_AUTH, &$auth_info);

        default:
            $err = sprintf('invalid openid.mode (%s) for GET requests', $mode);
            return $this->getError($auth_info->args, $err);
        }
    }

    /**
     * @access private
     */
    function _getAuthAuthorized(&$auth_info, $return_to)
    {
        $mode = $auth_info->getMode();
        switch ($mode) {
        case 'checkid_immediate':
        case 'checkid_setup':
            break;
        default:
            $err = sprintf('invalid openid.mode (%s) for GET requests', $mode);
            return $this->getError($auth_info->args, $err);
        }

        $reply = array('openid.mode' => 'id_res',
                       'openid.return_to' => $return_to,
                       'openid.identity' => $auth_info->getIdentityURL()
                       );

        $assoc = null;
        $assoc_handle = @$auth_info->args['openid.assoc_handle'];
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
        $redir_url = Auth_OpenID_appendArgs($return_to, $reply);
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
            return self.postError(sprinft($fmt, $assoc_type));
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
        $reply_kv = Auth_OpenID_arrayToKV($reply);
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
        
        $kv = Auth_OpenID_arrayToKV($reply);
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
            $secret = Auth_OpenID_getBytes(20);
        } else {
            // XXX: log
            return false;
        }

        $uniq = base64_encode(Auth_OpenID_getBytes(4));
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
    function getError($args, $msg)
    {
        $return_to = @$args['openid.return_to'];
        if (isset($return_to)) {
            $err = array(
                         'openid.mode' => 'error',
                         'openid.error' => $msg
                         );
            $redir_url = Auth_OpenID_appendArgs($return_to, $err);
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
        $kv = Auth_OpenID_arrayToKV(array('error' => $msg));
        return array(Auth_OpenID_REMOTE_ERROR, $kv);
    }
}

/**
 * Object that represents a server request
 *
 * With accessor functions to get at the internal request data.
 *
 * @package OpenID
 */
class Auth_OpenID_AuthorizationInfo {
    /**
     * The arguments for this request
     */
    var $args;

    /**
     * The URL of the server for this request
     */
    var $server_url;

    /**
     * Constructor
     *
     * @internal This is private because the library user should not
     * have to make instances of this class.
     *
     * @access private
     *
     * @param string $server_url The openid.server URL for the server
     * that goes with this request.
     *
     * @param array $args The query arguments for this request
     */
    function Auth_OpenID_AuthorizationInfo($server_url, $args)
    {
        $this->server_url = $server_url;
        $this->args = $args;
    }

    /**
     * @access private
     */
    function getMode()
    {
        return $this->args['openid.mode'];
    }

    /**
     * Get the identity URL that is being checked
     */
    function getIdentityURL()
    {
        return @$this->args['openid.identity'];
    }

    /**
     * Get the return_to URL for the consumer that initiated this request.
     *
     * @return string $return_to The return_to URL for the consumer
     */
    function getReturnTo()
    {
        return @$this->args['openid.return_to'];
    }

    /**
     * Get a cancel response for this URL
     *
     * @return array $response The status code and data
     */
    function cancel()
    {
        return array(Auth_OpenID_REDIRECT, $this->getCancelURL());
    }

    /**
     * Return a cancel URL for this request
     */
    function getCancelURL()
    {
        $cancel_args = array('openid.mode' => 'cancel');
        $return_to = $this->args['openid.return_to'];
        return Auth_OpenID_appendArgs($return_to, $cancel_args);
    }

    /**
     * Get a URL that will initiate this request again.
     */
    function getRetryURL()
    {
        return Auth_OpenID_appendArgs($this->server_url, $this->args);
    }

    /**
     * Return the trust_root for this request
     */
    function getTrustRoot()
    {
        if (isset($this->args['openid.trust_root'])) {
            return $this->args['openid.trust_root'];
        } else {
            return @$this->args['openid.return_to'];
        }
    }

    /**
     * Attempt to authenticate again, given a server and
     * authentication checking function.
     *
     * @param object $server An instance of Auth_OpenID_Server
     *
     * @param mixed $is_authorized The callback to use to determine
     * whether the current user can authorize this request.
     */
    function retry(&$server, $is_authorized)
    {
        $trust_root = $this->getTrustRoot();
        $identity_url = $this->getIdentityURL();

        // If there is no return_to or trust_root or there is no
        // identity_url, then it's impossible to continue.
        if (isset($identity_url) && isset($trust_root) && $is_authorized) {
            $authorized = $is_authorized($identity_url, $trust_root);
        } else {
            $authorized = false;
        }

        return $server->getAuthResponse(&$this, $authorized);
    }
}
