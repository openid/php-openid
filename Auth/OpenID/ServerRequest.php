<?php
/**
 * OpenID Server Request
 *
 * @see Auth_OpenID_Server
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
 * Imports
 */
require_once "Auth/OpenID.php";

/**
 * Object that holds the state of a request to the OpenID server
 *
 * With accessor functions to get at the internal request data.
 *
 * @see Auth_OpenID_Server
 * @package OpenID
 */
class Auth_OpenID_ServerRequest {
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
    function Auth_OpenID_ServerRequest($server_url, $args)
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
        return Auth_OpenID::appendArgs($return_to, $cancel_args);
    }

    /**
     * Get a URL that will initiate this request again.
     */
    function getRetryURL()
    {
        return Auth_OpenID::appendArgs($this->server_url, $this->args);
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
     * @param object $server An instance of {@link Auth_OpenID_Server}
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

?>