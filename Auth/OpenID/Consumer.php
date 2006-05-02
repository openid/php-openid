<?php

/**
 * This module documents the main interface with the OpenID consumer
 * libary. The only part of the library which has to be used and isn't
 * documented in full here is the store required to create an
 * OpenIDConsumer instance. More on the abstract store type and
 * concrete implementations of it that are provided in the
 * documentation for the constructor of the OpenIDConsumer class.
 *
 * OVERVIEW
 *
 * The OpenID identity verification process most commonly uses the
 * following steps, as visible to the user of this library:
 *
 * 1. The user enters their OpenID into a field on the consumer's
 *    site, and hits a login button.
 * 2. The consumer site checks that the entered URL describes an
 *    OpenID page by fetching it and looking for appropriate link tags
 *    in the head section.
 * 3. The consumer site sends the browser a redirect to the identity
 *    server.  This is the authentication request as described in the
 *    OpenID specification.
 * 4. The identity server's site sends the browser a redirect back to
 *    the consumer site.  This redirect contains the server's response
 *    to the authentication request.
 *
 * The most important part of the flow to note is the consumer's site
 * must handle two separate HTTP requests in order to perform the full
 * identity check.
 *
 * LIBRARY DESIGN
 *
 * This consumer library is designed with that flow in mind.  The goal
 * is to make it as easy as possible to perform the above steps
 * securely.
 *
 * At a high level, there are two important parts in the consumer
 * library.  The first important part is this module, which contains
 * the interface to actually use this library.  The second is the
 * {@link Auth_OpenID_OpenIDStore} class, which describes the
 * interface to use if you need to create a custom method for storing
 * the state this library needs to maintain between requests.
 *
 * In general, the second part is less important for users of the
 * library to know about, as several implementations are provided
 * which cover a wide variety of situations in which consumers may
 * use the library.
 *
 * This module contains a class, {@link Auth_OpenID_Consumer}, with
 * methods corresponding to the actions necessary in each of steps 2,
 * 3, and 4 described in the overview.  Use of this library should be
 * as easy as creating a {@link Auth_OpenID_Consumer} instance and
 * calling the methods appropriate for the action the site wants to
 * take.
 *
 * STORES AND DUMB MODE
 *
 * OpenID is a protocol that works best when the consumer site is able
 * to store some state.  This is the normal mode of operation for the
 * protocol, and is sometimes referred to as smart mode.  There is
 * also a fallback mode, known as dumb mode, which is available when
 * the consumer site is not able to store state.  This mode should be
 * avoided when possible, as it leaves the implementation more
 * vulnerable to replay attacks.
 *
 * The mode the library works in for normal operation is determined by
 * the store that it is given.  The store is an abstraction that
 * handles the data that the consumer needs to manage between http
 * requests in order to operate efficiently and securely.
 *
 * Several store implementation are provided, and the interface is
 * fully documented so that custom stores can be used as well.  See
 * the documentation for the {@link Auth_OpenID_Consumer} class for
 * more information on the interface for stores.  The concrete
 * implementations that are provided allow the consumer site to store
 * the necessary data in several different ways: in the filesystem, in
 * a MySQL database, or in an SQLite database.
 *
 * There is an additional concrete store provided that puts the system
 * in dumb mode.  This is not recommended, as it removes the library's
 * ability to stop replay attacks reliably.  It still uses time-based
 * checking to make replay attacks only possible within a small
 * window, but they remain possible within that window.  This store
 * should only be used if the consumer site has no way to retain data
 * between requests at all.
 *
 * IMMEDIATE MODE
 *
 * In the flow described above, the user may need to confirm to the
 * identity server that it's ok to authorize his or her identity.  The
 * server may draw pages asking for information from the user before
 * it redirects the browser back to the consumer's site.  This is
 * generally transparent to the consumer site, so it is typically
 * ignored as an implementation detail.
 *
 * There can be times, however, where the consumer site wants to get a
 * response immediately.  When this is the case, the consumer can put
 * the library in immediate mode.  In immediate mode, there is an
 * extra response possible from the server, which is essentially the
 * server reporting that it doesn't have enough information to answer
 * the question yet.  In addition to saying that, the identity server
 * provides a URL to which the user can be sent to provide the needed
 * information and let the server finish handling the original
 * request.
 *
 * USING THIS LIBRARY
 *
 * Integrating this library into an application is usually a
 * relatively straightforward process.  The process should basically
 * follow this plan:
 *
 * Add an OpenID login field somewhere on your site.  When an OpenID
 * is entered in that field and the form is submitted, it should make
 * a request to the your site which includes that OpenID URL.
 *
 * When your site receives that request, it should create an
 * {@link Auth_OpenID_Consumer} instance, and call beginAuth on it.
 * If beginAuth completes successfully, it will return an
 * {@link Auth_OpenID_AuthenticationRequest} instance.  Otherwise it
 * will provide some useful information for giving the user an error
 * message.
 *
 * Now that you have the {@link Auth_OpenID_AuthenticationRequest}
 * object, you need to preserve the value in its $token field for
 * lookup on the user's next request from your site.  There are
 * several approaches for doing this which will work.  If your
 * environment has any kind of session-tracking system, storing the
 * token in the session is a good approach.  If it doesn't you can
 * store the token in either a cookie or in the return_to url provided
 * in the next step.
 *
 * The next step is to call the constructRedirect method on the
 * {@link Auth_OpenID_Consumer} object.  Pass it the
 * {@link Auth_OpenID_AuthenticationRequest} object returned by the previous
 * call to beginAuth along with the return_to and trust_root URLs.
 * The return_to URL is the URL that the OpenID server will send the
 * user back to after attempting to verify his or her identity.  The
 * trust_root is the URL (or URL pattern) that identifies your web
 * site to the user when he or she is authorizing it.
 *
 * Next, send the user a redirect to the URL generated by
 * constructRedirect.
 *
 * That's the first half of the process.  The second half of the
 * process is done after the user's ID server sends the user a
 * redirect back to your site to complete their login.
 *
 * When that happens, the user will contact your site at the URL given
 * as the return_to URL to the constructRedirect call made above.  The
 * request will have several query parameters added to the URL by the
 * identity server as the information necessary to finish the request.
 *
 * When handling this request, the first thing to do is check the
 * 'openid.return_to' parameter.  If it doesn't match the URL that
 * the request was actually sent to (the URL the request was actually
 * sent to will contain the openid parameters in addition to any in
 * the return_to URL, but they should be identical other than that),
 * that is clearly suspicious, and the request shouldn't be allowed to
 * proceed.

 * Otherwise, the next step is to extract the token value set in the
 * first half of the OpenID login.  Create a {@link Auth_OpenID_Consumer}
 * object, and call its completeAuth method with that token and a
 * dictionary of all the query arguments.  This call will return a
 * status code and some additional information describing the the
 * server's response.  See the documentation for completeAuth for a
 * full explanation of the possible responses.
 *
 * At this point, you have an identity URL that you know belongs to
 * the user who made that request.  Some sites will use that URL
 * directly as the user name.  Other sites will want to map that URL
 * to a username in the site's traditional namespace.  At this point,
 * you can take whichever action makes the most sense.
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
 * Require utility classes and functions for the consumer.
 */
require_once "Auth/OpenID.php";
require_once "Auth/OpenID/HMACSHA1.php";
require_once "Auth/OpenID/Association.php";
require_once "Auth/OpenID/AuthenticationRequest.php";
require_once "Auth/OpenID/CryptUtil.php";
require_once "Auth/OpenID/DiffieHellman.php";
require_once "Auth/OpenID/KVForm.php";
require_once "Auth/OpenID/Discover.php";

/**
 * This is the status code returned when either the of the beginAuth
 * or completeAuth methods return successfully.
 */
define('Auth_OpenID_SUCCESS', 'success');

/**
 * This is the status code completeAuth returns when the value it
 * received indicated an invalid login.
 */
define('Auth_OpenID_FAILURE', 'failure');

/**
 * This is the status code completeAuth returns when the
 * {@link Auth_OpenID_Consumer} instance is in immediate mode, and the
 * identity server sends back a URL to send the user to to complete his
 * or her login.
 */
define('Auth_OpenID_SETUP_NEEDED', 'setup needed');

/**
 * This is the status code beginAuth returns when the page fetched
 * from the entered OpenID URL doesn't contain the necessary link tags
 * to function as an identity page.
 */
define('Auth_OpenID_PARSE_ERROR', 'parse error');

/**
 * This is the characters that the nonces are made from.
 */
define('Auth_OpenID_DEFAULT_NONCE_CHRS',"abcdefghijklmnopqrstuvwxyz" .
       "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");

/**
 * This is the number of seconds the tokens generated by this library
 * will be valid for.  If you want to change the lifetime of a token,
 * set this value to the desired lifespan, in seconds.
 */
define('Auth_OpenID_DEFAULT_TOKEN_LIFETIME', 60 * 5); // five minutes

class Auth_OpenID_Session {
    function set($name, $value)
    {
        $_SESSION[$name] = $value;
    }

    function get($name, $default=null)
    {
        if (array_key_exists($name, $_SESSION)) {
            return $_SESSION[$name];
        } else {
            return $default;
        }
    }

    function del($name)
    {
        unset($_SESSION[$name]);
    }
}

class Auth_OpenID_Consumer {

    var $session_key_prefix = "_openid_consumer_";
    var $_token_suffix = "last_token";

    function Auth_OpenID_Consumer(&$session, &$store)
    {
        $this->session =& $session;
        $this->consumer =& new Auth_OpenID_GenericConsumer($store);
        $this->_token_key = $this->session_key_prefix . $this->_token_suffix;
    }

    function begin($user_url)
    {
        $openid_url = Auth_OpenID::normalizeUrl($user_url);
        if (false) { // If yadis_available
        } else {
            $endpoint = null;
            $result = Auth_OpenID_discover($openid_url, $this->consumer->fetcher);
            if ($result !== null) {
                list($temp, $endpoints) = $result;
                $endpoint = $endpoints[0];
            }
        }

        if ($endpoint === null) {
            return null;
        } else {
            return $this->beginWithoutDiscovery($endpoint);
        }
    }

    function &beginWithoutDiscovery($endpoint)
    {
        $auth_req = $this->consumer->begin($endpoint);
        $this->session->set($this->_token_key, $auth_req->token);
        return $auth_req;
    }

    function complete($query)
    {
        $token = $this->session->get($this->_token_key);

        if ($token === null) {
            $response = new Auth_OpenID_FailureResponse(null, 'No session state found');
        } else {
            $response = $this->consumer->complete($query, $token);
        }

        if (in_array($response->status, array('success', 'cancel'))) {
            /*
            if yadis_available and response.identity_url is not None:
                disco = Discovery(self.session, response.identity_url)
                # This is OK to do even if we did not do discovery in
                # the first place.
                disco.cleanup()
             */
        }

        return $response;
    }
}

/**
 * This class is the interface to the OpenID consumer logic.
 * Instances of it maintain no per-request state, so they can be
 * reused (or even used by multiple threads concurrently) as needed.
 *
 * @package OpenID
 */
class Auth_OpenID_GenericConsumer {
    /**
     * This consumer's store object.
     */
    var $store;

    /**
     * @access private
     */
    var $_use_assocs;

    /**
     * This is the number of characters in the generated nonce for
     * each transaction.
     */
    var $nonce_len = 8;

    /**
     * What characters are allowed in nonces
     */
    var $nonce_chrs = Auth_OpenID_DEFAULT_NONCE_CHRS;

    /**
     * How long should an authentication session stay good?
     *
     * In units of sections. Shorter times mean less opportunity for
     * attackers, longer times mean less chance of a user's session
     * timing out.
     */
    var $token_lifetime = Auth_OpenID_DEFAULT_TOKEN_LIFETIME;

    /**
     * This method initializes a new {@link Auth_OpenID_Consumer}
     * instance to access the library.
     *
     * @param Auth_OpenID_OpenIDStore $store This must be an object
     * that implements the interface in {@link Auth_OpenID_OpenIDStore}.
     * Several concrete implementations are provided, to cover most common use
     * cases.  For stores backed by MySQL, PostgreSQL, or SQLite, see
     * the {@link Auth_OpenID_SQLStore} class and its sublcasses.  For a
     * filesystem-backed store, see the {@link Auth_OpenID_FileStore} module.
     * As a last resort, if it isn't possible for the server to store
     * state at all, an instance of {@link Auth_OpenID_DumbStore} can be used.
     * This should be an absolute last resort, though, as it makes the
     * consumer vulnerable to replay attacks over the lifespan of the
     * tokens the library creates.
     *
     * @param bool $immediate This is an optional boolean value.  It
     * controls whether the library uses immediate mode, as explained
     * in the module description.  The default value is False, which
     * disables immediate mode.
     */
    function Auth_OpenID_GenericConsumer(&$store)
    {
        if ($store === null) {
            trigger_error("Must supply non-null store to create consumer",
                          E_USER_ERROR);
            return null;
        }

        $this->store =& $store;
        $this->_use_assocs =
            !(defined('Auth_OpenID_NO_MATH_SUPPORT') ||
              $this->store->isDumb());

        $this->fetcher = Auth_OpenID::getHTTPFetcher();
    }

    function begin($service_endpoint)
    {
        $nonce = $this->_createNonce();
        $token = $this->_genToken($nonce,
                                  $service_endpoint->identity_url,
                                  $service_endpoint->getServerID(),
                                  $service_endpoint->server_url);
        $assoc = $this->_getAssociation($service_endpoint->server_url);
        $r = new Auth_OpenID_AuthRequest($token, $assoc, $service_endpoint);
        $r->return_to_args['nonce'] = $nonce;
        return $r;
    }

    function complete($query, $token)
    {
        $mode = Auth_OpenID::arrayGet($query, 'openid.mode', '<no mode specified>');

        $pieces = $this->_splitToken($token);
        if ($pieces === null) {
            $pieces = array(null, null, null);
        }

        list($nonce, $identity_url, $delegate, $server_url) = $pieces;

        if ($mode == 'cancel') {
            return new Auth_OpenID_CancelResponse($identity_url);
        } else if ($mode == 'error') {
            $error = Auth_OpenID::arrayGet($query, 'openid.error');
            return new Auth_OpenID_FailureResponse($identity_url, $error);
        } else if ($mode == 'id_res') {
            if ($identity_url === null) {
                return new Auth_OpenID_FailureResponse($identity_url, "No session state found");
            }

            $response = $this->_doIdRes($query, $identity_url, $delegate, $server_url);

            if ($response === null) {
                return new Auth_OpenID_FailureResponse($identity_url,
                                                       "HTTP request failed");
            }
            if ($response->status == Auth_OpenID_SUCCESS) {
                return $this->_checkNonce($response,
                                          Auth_OpenID::arrayGet($query, 'nonce'));
            } else {
                return $response;
            }
        } else {
            return new Auth_OpenID_FailureResponse($identity_url,
                                                   sprintf("Invalid openid.mode '%s'",
                                                           $mode));
        }
    }

    /**
     * @access private
     */
    function _doIdRes($query, $consumer_id, $server_id, $server_url)
    {
        $user_setup_url = Auth_OpenID::arrayGet($query,
                                                'openid.user_setup_url');

        if ($user_setup_url !== null) {
            return new Auth_OpenID_SetupNeededResponse($consumer_id,
                                                       $user_setup_url);
        }

        $return_to = Auth_OpenID::arrayGet($query, 'openid.return_to', null);
        $server_id2 = Auth_OpenID::arrayGet($query, 'openid.identity', null);
        $assoc_handle = Auth_OpenID::arrayGet($query,
                                             'openid.assoc_handle', null);

        if (($return_to === null) ||
            ($server_id === null) ||
            ($assoc_handle === null)) {
            return new Auth_OpenID_FailureResponse($consumer_id,
                                                   "Missing required field");
        }

        if ($server_id != $server_id2) {
            return new Auth_OpenID_FailureResponse($consumer_id,
                                                   "Server ID (delegate) mismatch");
        }

        $signed = Auth_OpenID::arrayGet($query, 'openid.signed');

        $assoc = $this->store->getAssociation($server_url, $assoc_handle);

        if ($assoc === null) {
            // It's not an association we know about.  Dumb mode is
            // our only possible path for recovery.
            if ($this->_checkAuth($query, $server_url)) {
                return new Auth_OpenID_SuccessResponse($consumer_id, $query,
                                                       $signed);
            } else {
                return new Auth_OpenID_FailureResponse($consumer_id,
                                          "Server denied check_authentication");
            }
        }

        if ($assoc->getExpiresIn() <= 0) {
            $msg = sprintf("Association with %s expired", $server_url);
            return new Auth_OpenID_FailureResponse($consumer_id, $msg);
        }

        // Check the signature
        $sig = Auth_OpenID::arrayGet($query, 'openid.sig', null);
        $signed = Auth_OpenID::arrayGet($query, 'openid.signed', null);
        if (($sig === null) ||
            ($signed === null)) {
            return new Auth_OpenID_FailureResponse($consumer_id,
                                                   "Missing argument signature");
        }

        $signed_list = explode(",", $signed);
        $v_sig = $assoc->signDict($signed_list, $query);

        if ($v_sig != $sig) {
            return new Auth_OpenID_FailureResponse($consumer_id, "Bad signature");
        }

        return Auth_OpenID_SuccessResponse::fromQuery($consumer_id, $query, $signed);
    }

    function _checkAuth($query, $server_url)
    {
        $request = $this->_createCheckAuthRequest($query);
        if ($request === null) {
            return false;
        }

        $response = $this->_makeKVPost($request, $server_url);
        if ($response == null) {
            return false;
        }

        return $this->_processCheckAuthResponse($response);
    }

    /**
     * @access private
     */
    function _createCheckAuthRequest($query)
    {
        $signed = Auth_OpenID::arrayGet($query, 'openid.signed', null);
        if ($signed === null) {
            return null;
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
        return $check_args;
    }

    function _processCheckAuthResponse($response)
    {
        $is_valid = Auth_OpenID::arrayGet($response, 'is_valid', 'false');

        if ($is_valid == 'true') {
            $invalidate_handle = Auth_OpenID::arrayGet($results,
                                                       'invalidate_handle');

            if ($invalidate_handle !== null) {
                $this->store->removeAssociation($server_url,
                                                $invalidate_handle);
            }

            return true;
        }

        return false;
    }

    function _makeKVPost($args, $server_url)
    {
        $mode = $args['openid.mode'];

        $pairs = array();
        foreach ($args as $k => $v) {
            $v = urlencode($v);
            $pairs[] = "$k=$v";
        }

        $body = implode("&", $pairs);

        $resp = $this->fetcher->post($server_url, $body);

        if ($res === null) {
            return null;
        }

        list($code, $url, $resp_body) = $resp;

        $response = Auth_OpenID_KVForm::toArray($resp_body);

        if ($code == 400) {
            return null;
        } else if ($code != 200) {
            return null;
        }

        return $response;
    }

    function _checkNonce($response, $nonce)
    {
        $parsed_url = parse_url($response->getReturnTo());
        $query_str = @$parsed_url['query'];
        $query = array();
        parse_str($query_str, $query);

        $found = false;

        foreach ($query as $k => $v) {
            if ($k == 'nonce') {
                if ($v != $nonce) {
                    return new Auth_OpenID_FailureResponse($response->identity_url,
                                                           "Nonce mismatch");
                } else {
                    $found = true;
                    break;
                }
            }
        }

        if (!$found) {
            return new Auth_OpenID_FailureResponse($response->identity_url,
                                 sprintf("Nonce missing from return_to: %s",
                                         $response->getReturnTo()));
        }

        if (!$this->store->useNonce($nonce)) {
            return new Auth_OpenID_FailureResponse($response->identity_url,
                                                   "Nonce missing from store");
        }

        return $response;
    }

    function _createNonce()
    {
        $nonce = Auth_OpenID_CryptUtil::randomString($this->nonce_len,
                                                     $this->nonce_chrs);
        $this->store->storeNonce($nonce);
        return $nonce;
    }

    /**
     * @access protected
     */
    function _createDiffieHellman()
    {
        return new Auth_OpenID_DiffieHellman();
    }

    /**
     * @access private
     */
    function _getAssociation($server_url, $replace = false)
    {
        if (!$this->_use_assocs) {
            return null;
        }

        $assoc = $this->store->getAssociation($server_url);

        if (($assoc === null) ||
            ($replace && ($assoc->getExpiresIn() < $this->token_lifetime))) {

            $args = array(
                          'openid.mode' =>  'associate',
                          'openid.assoc_type' => 'HMAC-SHA1',
                          );

            $dh = $this->_createDiffieHellman();
            $args = array_merge($args, $dh->getAssocArgs());
            $body = Auth_OpenID::httpBuildQuery($args);

            $assoc = $this->_fetchAssociation($dh, $server_url, $body);
        }

        return $assoc;
    }

    /**
     * @access private
     */
    function _genToken($nonce, $consumer_id, $server_id, $server_url)
    {
        $timestamp = strval(time());
        $elements = array($timestamp, $nonce,
                          $consumer_id, $server_id, $server_url);

        $joined = implode("\x00", $elements);
        $sig = Auth_OpenID_HMACSHA1($this->store->getAuthKey(),
                                              $joined);

        return base64_encode($sig . $joined);
    }

    /**
     * @access private
     */
    function _splitToken($token)
    {
        $token = base64_decode($token);
        if (strlen($token) < 20) {
            return null;
        }

        $sig = substr($token, 0, 20);
        $joined = substr($token, 20);
        $check_sig = Auth_OpenID_HMACSHA1($this->store->getAuthKey(), $joined);
        if ($check_sig != $sig) {
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

        if ($ts + $this->token_lifetime < time()) {
            return null;
        }

        return array_slice($split, 1);
    }

    /**
     * @access private
     */
    function _fetchAssociation($dh, $server_url, $body)
    {
        $ret = @$this->fetcher->post($server_url, $body);
        if ($ret === null) {
            $fmt = 'Getting association: failed to fetch URL: %s';
            trigger_error(sprintf($fmt, $server_url), E_USER_NOTICE);
            return null;
        }

        list($http_code, $url, $data) = $ret;
        $results = Auth_OpenID_KVForm::toArray($data);
        if ($http_code == 400) {
            $error = Auth_OpenID::arrayGet($results, 'error',
                                           '<no message from server>');

            $fmt = 'Getting association: error returned from server %s: %s';
            trigger_error(sprintf($fmt, $server_url, $error), E_USER_NOTICE);
            return null;
        } else if ($http_code != 200) {
            $fmt = 'Getting association: bad status code from server %s: %s';
            $msg = sprintf($fmt, $server_url, $http_code);
            trigger_error($msg, E_USER_NOTICE);
            return null;
        }

        $results = Auth_OpenID_KVForm::toArray($data);

        return $this->_parseAssociation($results, $dh, $server_url);
    }

    /**
     * @access private
     */
    function _parseAssociation($results, $dh, $server_url)
    {
        $required_keys = array('assoc_type', 'assoc_handle',
                               'dh_server_public', 'enc_mac_key');

        foreach ($required_keys as $key) {
            if (!array_key_exists($key, $results)) {
                $fmt = "associate: missing key in response from %s: %s";
                $msg = sprintf($fmt, $server_url, $key);
                trigger_error($msg, E_USER_NOTICE);
                return null;
            }
        }

        $assoc_type = $results['assoc_type'];
        if ($assoc_type != 'HMAC-SHA1') {
            $fmt = 'Unsupported assoc_type returned from server %s: %s';
            $msg = sprintf($fmt, $server_url, $assoc_type);
            trigger_error($msg, E_USER_NOTICE);
            return null;
        }

        $assoc_handle = $results['assoc_handle'];
        $expires_in = intval(Auth_OpenID::arrayGet($results, 'expires_in',
                             '0'));

        $session_type = Auth_OpenID::arrayGet($results, 'session_type', null);
        if ($session_type === null) {
            $secret = base64_decode($results['mac_key']);
        } else {
            $fmt = 'Unsupported session_type returned from server %s: %s';
            if ($session_type != 'DH-SHA1') {
                $msg = sprintf($fmt, $server_url, $session_type);
                trigger_error($msg, E_USER_NOTICE);
                return null;
            }

            $secret = $dh->consumerFinish($results);
        }

        $assoc = Auth_OpenID_Association::fromExpiresIn($expires_in,
                                                       $assoc_handle,
                                                       $secret,
                                                       $assoc_type);

        $this->store->storeAssociation($server_url, $assoc);
        return $assoc;
    }
}

class Auth_OpenID_AuthRequest {
    function Auth_OpenID_AuthRequest($token, $assoc, $endpoint)
    {
        $this->assoc = $assoc;
        $this->endpoint = $endpoint;
        $this->extra_args = array();
        $this->return_to_args = array();
        $this->token = $token;
    }

    function addExtensionArg($namespace, $key, $value)
    {
        $arg_name = implode('.', array('openid', $namespace, $key));
        $this->extra_args[$arg_name] = $value;
    }

    function redirectURL($trust_root, $return_to, $immediate=false)
    {
        if ($immediate) {
            $mode = 'checkid_immediate';
        } else {
            $mode = 'checkid_setup';
        }

        $return_to = Auth_OpenID::appendArgs($return_to, $this->return_to_args);

        $redir_args = array(
            'openid.mode' => $mode,
            'openid.identity' => $this->endpoint->getServerID(),
            'openid.return_to' => $return_to,
            'openid.trust_root' => $trust_root);

        if ($this->assoc) {
            $redir_args['openid.assoc_handle'] = $this->assoc->handle;
        }

        $redir_args = array_merge($redir_args, $this->extra_args);
        return Auth_OpenID::appendArgs($this->endpoint->server_url, $redir_args);
    }
}

class Auth_OpenID_ConsumerResponse {
    var $status = null;
}

class Auth_OpenID_SuccessResponse extends Auth_OpenID_ConsumerResponse {
    var $status = 'success';

    function Auth_OpenID_SuccessResponse($identity_url, $signed_args)
    {
        $this->identity_url = $identity_url;
        $this->signed_args = $signed_args;
    }

    function fromQuery($identity_url, $query, $signed)
    {
        $signed_args = array();
        foreach (explode(",", $signed) as $field_name) {
            $field_name = 'openid.' . $field_name;
            $signed_args[$field_name] = Auth_OpenID::arrayGet($query, $field_name, '');
        }
        return new Auth_OpenID_SuccessResponse($identity_url, $signed_args);
    }

    function extensionResponse($prefix)
    {
        $response = array();
        $prefix = sprintf('openid.%s.', $prefix);
        $prefix_len = strlen($prefix);
        foreach ($this->signed_args as $k => $v) {
            if (strpos($k, $prefix) === 0) {
                $response_key = substring($k, $prefix_len);
                $response[$response_key] = $v;
            }
        }

        return $response;
    }

    function getReturnTo()
    {
        return $this->signed_args['openid.return_to'];
    }
}

class Auth_OpenID_FailureResponse extends Auth_OpenID_ConsumerResponse {
    var $status = 'failure';

    function Auth_OpenID_FailureResponse($identity_url = null, $message = null)
    {
        $this->identity_url = $identity_url;
        $this->message = $message;
    }
}

class Auth_OpenID_CancelResponse extends Auth_OpenID_ConsumerResponse {
    var $status = 'cancelled';

    function Auth_OpenID_CancelResponse($identity_url = null)
    {
        $this->identity_url = $identity_url;
    }
}

class Auth_OpenID_SetupNeededResponse extends Auth_OpenID_ConsumerResponse {
    var $status = 'setup_needed';

    function Auth_OpenID_SetupNeededResponse($identity_url = null,
                                             $setup_url = null)
    {
        $this->identity_url = $identity_url;
        $this->setup_url = $setup_url;
    }
}

?>
