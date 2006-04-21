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
require_once "Auth/OpenID/BigMath.php";
require_once "Auth/OpenID/DiffieHellman.php";
require_once "Auth/OpenID/KVForm.php";
require_once "Auth/OpenID/TrustRoot.php";
require_once "Auth/OpenID/ServerRequest.php";

define('AUTH_OPENID_HTTP_OK', 200);
define('AUTH_OPENID_HTTP_REDIRECT', 302);
define('AUTH_OPENID_HTTP_ERROR', 400);

global $_Auth_OpenID_Request_Modes,
    $_Auth_OpenID_OpenID_Prefix,
    $_Auth_OpenID_Encode_Kvform,
    $_Auth_OpenID_Encode_Url;

$_Auth_OpenID_Request_Modes = array('checkid_setup',
                                    'checkid_immediate');
$_Auth_OpenID_OpenID_Prefix = "openid.";
$_Auth_OpenID_Encode_Kvform = array('kfvorm');
$_Auth_OpenID_Encode_Url = array('URL/redirect');

function _isError($obj, $cls = 'Auth_OpenID_ServerError')
{
    return is_a($obj, $cls);
}

class Auth_OpenID_ServerError {
    function Auth_OpenID_ServerError($query = null, $message = null)
    {
        $this->message = $message;
        $this->query = $query;
    }

    function hasReturnTo()
    {
        global $_Auth_OpenID_OpenID_Prefix;
        return array_key_exists($_Auth_OpenID_OpenID_Prefix . 'return_to',
                                $this->query);
    }

    function encodeToURL()
    {
        global $_Auth_OpenID_OpenID_Prefix;
        $return_to = Auth_OpenID::arrayGet($this->query,
                                           $_Auth_OpenID_OpenID_Prefix .
                                           'return_to');
        if (!$return_to) {
            return new Auth_OpenID_ServerError(null, "no return_to URL");
        }

        return Auth_OpenID::appendArgs($return_to,
                                       array('openid.mode' => 'error',
                                             'error' => $this->toString()));
    }

    function encodeToKVForm()
    {
        return Auth_OpenID_KVForm::fromArray(
                                      array('mode' => 'error',
                                            'error' => $this->toString()));
    }

    function whichEncoding()
    {
        global $_Auth_OpenID_Encode_Url,
            $_Auth_OpenID_Encode_Kvform,
            $_Auth_OpenID_Request_Modes;

        if ($this->hasReturnTo()) {
            return $_Auth_OpenID_Encode_Url;
        }

        $mode = Auth_OpenID::arrayGet($this->query, 'openid.mode');

        if ($mode) {
            if (!in_array($mode, $_Auth_OpenID_Request_Modes)) {
                return $_Auth_OpenID_Encode_Kvform;
            }
        }
        return null;
    }

    function toString()
    {
        if ($this->message) {
            return $this->message;
        } else {
            return get_class($this) . " error";
        }
    }
}

class Auth_OpenID_MalformedReturnURL extends Auth_OpenID_ServerError {
    function Auth_OpenID_MalformedReturnURL($query, $return_to)
    {
        $this->return_to = $return_to;
        parent::Auth_OpenID_ServerError($query, "malformed return_to URL");
    }
}

class Auth_OpenID_MalformedTrustRoot extends Auth_OpenID_ServerError {
    function toString()
    {
        return "Malformed trust root";
    }
}

class Auth_OpenID_Request {
    var $mode = null;
}

class Auth_OpenID_CheckAuthRequest extends Auth_OpenID_Request {
    var $mode = "check_authentication";
    var $invalidate_handle = null;

    function Auth_OpenID_CheckAuthRequest($assoc_handle, $sig, $signed,
                                          $invalidate_handle = null)
    {
        $this->assoc_handle = $assoc_handle;
        $this->sig = $sig;
        $this->signed = $signed;
        if ($invalidate_handle !== null) {
            $this->invalidate_handle = $invalidate_handle;
        }
    }

    function fromQuery($query)
    {
        global $_Auth_OpenID_OpenID_Prefix;

        $required_keys = array('assoc_handle', 'sig', 'signed');

        foreach ($required_keys as $k) {
            if (!array_key_exists($_Auth_OpenID_OpenID_Prefix . $k,
                                  $query)) {
                return new Auth_OpenID_ServerError($query,
                    sprintf("%s request missing required parameter %s from \
                            query", $this->mode, $k));
            }
        }

        $assoc_handle = $query[$_Auth_OpenID_OpenID_Prefix . 'assoc_handle'];
        $sig = $query[$_Auth_OpenID_OpenID_Prefix . 'sig'];
        $signed_list = $query[$_Auth_OpenID_OpenID_Prefix . 'signed'];

        $signed_list = explode(",", $signed_list);
        $signed_pairs = array();

        foreach ($signed_list as $field) {
            if ($field == 'mode') {
                // XXX KLUDGE HAX WEB PROTOCoL BR0KENNN
                //
                // openid.mode is currently check_authentication
                // because that's the mode of this request.  But the
                // signature was made on something with a different
                // openid.mode.
                $value = "id_res";
            } else {
                if (array_key_exists($_Auth_OpenID_OpenID_Prefix . $field,
                                     $query)) {
                    $value = $query[$_Auth_OpenID_OpenID_Prefix . $field];
                } else {
                    return new Auth_OpenID_ServerError($query,
                          sprintf("Couldn't find signed field %r in query %s",
                                  $field));
                }
            }
            $signed_pairs[] = array($field, $value);
        }

        return new Auth_OpenID_CheckAuthRequest($assoc_handle, $sig,
                                                $signed_pairs);
    }

    function answer(&$signatory)
    {
        $is_valid = $signatory->verify($this->assoc_handle, $this->sig,
                                       $this->signed);

        // Now invalidate that assoc_handle so it this checkAuth
        // message cannot be replayed.
        $signatory->invalidate($this->assoc_handle, true);
        $response = new Auth_OpenID_ServerResponse($this);
        $response->fields['is_valid'] = $is_valid ? "true" : "false";

        if ($this->invalidate_handle) {
            $assoc = $signatory->getAssociation($this->invalidate_handle,
                                                false);
            if (!$assoc) {
                $response->fields['invalidate_handle'] =
                    $this->invalidate_handle;
            }
        }
        return $response;
    }
}

class Auth_OpenID_AssociateRequest extends Auth_OpenID_Request {
    var $mode = "associate";
    var $session_type = 'plaintext';
    var $assoc_type = 'HMAC-SHA1';

    function fromQuery($query)
    {
        global $_Auth_OpenID_OpenID_Prefix;

        // FIXME: Missing dh_modulus and dh_gen options.
        $obj = new Auth_OpenID_AssociateRequest();

        $session_type = null;

        if (array_key_exists($_Auth_OpenID_OpenID_Prefix . 'session_type',
                             $query)) {
            $session_type = $query[$_Auth_OpenID_OpenID_Prefix .
                                   'session_type'];
        }

        if ($session_type) {
            $obj->session_type = $session_type;

            if ($session_type == 'DH-SHA1') {
                if (array_key_exists($_Auth_OpenID_OpenID_Prefix .
                                     'dh_consumer_public', $query)) {

                    # Auth_OpenID_getMathLib()
                    $lib =& Auth_OpenID_getMathLib();

                    $obj->pubkey = $lib->base64ToLong(
                                      $query[$_Auth_OpenID_OpenID_Prefix .
                                             'dh_consumer_public']);
                } else {
                    return new Auth_OpenID_ServerError($query,
                           "Public key for DH-SHA1 session not found in query");
                }
            }
        }

        return $obj;
    }

    function answer($assoc)
    {
        $ml =& Auth_OpenID_getMathLib();
        $response = new Auth_OpenID_ServerResponse($this);

        $response->fields = array('expires_in' => $assoc->getExpiresIn(),
                                  'assoc_type' => 'HMAC-SHA1',
                                  'assoc_handle' => $assoc->handle);

        if ($this->session_type == 'DH-SHA1') {
            // XXX - get dh_modulus and dh_gen
            $dh = new Auth_OpenID_DiffieHellman();
            $mac_key = $dh->xorSecret($this->pubkey, $assoc->secret);
            $response->fields['session_type'] = $this->session_type;
            $response->fields['dh_server_public'] =
                $ml->longToBase64($dh->public);
            $response->fields['enc_mac_key'] = base64_encode($mac_key);
        } else if ($this->session_type == 'plaintext') {
            $response->fields['mac_key'] = base64_encode($assoc->secret);
        } else {
            // XXX - kablooie
        }

        return $response;
    }
}

class Auth_OpenID_CheckIDRequest extends Auth_OpenID_Request {
    var $mode = "checkid_setup"; // or "checkid_immediate"
    var $immediate = false;
    var $trust_root = null;

    function make($query, $identity, $return_to, $trust_root = null,
                  $immediate = false, $assoc_handle = null)
    {
        if (!Auth_OpenID_TrustRoot::_parse($return_to)) {
            return new Auth_OpenID_MalformedReturnURL($query, $return_to);
        }

        return new Auth_OpenID_CheckIDRequest($identity, $return_to,
                                              $trust_root, $immediate,
                                              $assoc_handle);
    }

    function Auth_OpenID_CheckIDRequest($identity, $return_to,
                                        $trust_root = null, $immediate = false,
                                        $assoc_handle = null)
    {
        $this->identity = $identity;
        $this->return_to = $return_to;
        $this->trust_root = $trust_root;
        $this->assoc_handle = $assoc_handle;

        if ($immediate) {
            $this->immediate = true;
            $this->mode = "checkid_immediate";
        } else {
            $this->immediate = false;
            $this->mode = "checkid_setup";
        }
    }

    function fromQuery($query)
    {
        global $_Auth_OpenID_OpenID_Prefix;

        $mode = $query[$_Auth_OpenID_OpenID_Prefix . 'mode'];
        $immediate = null;

        if ($mode == "checkid_immediate") {
            $immediate = true;
            $mode = "checkid_immediate";
        } else {
            $immediate = false;
            $mode = "checkid_setup";
        }

        $required = array('identity',
                          'return_to');

        $optional = array('trust_root',
                          'assoc_handle');

        $values = array();

        foreach ($required as $field) {
            if (array_key_exists($_Auth_OpenID_OpenID_Prefix . $field,
                                 $query)) {
                $value = $query[$_Auth_OpenID_OpenID_Prefix . $field];
            } else {
                return new Auth_OpenID_ServerError($query,
                               sprintf("Missing required field %s from request",
                                       $field));
            }
            $values[$field] = $value;
        }

        foreach ($optional as $field) {
            $value = null;
            if (array_key_exists($_Auth_OpenID_OpenID_Prefix . $field,
                                 $query)) {
                $value = $query[$_Auth_OpenID_OpenID_Prefix. $field];
            }
            if ($value) {
                $values[$field] = $value;
            }
        }

        if (!Auth_OpenID_TrustRoot::_parse($values['return_to'])) {
            return new Auth_OpenID_MalformedReturnURL($query,
                                                      $values['return_to']);
        }

        $obj = Auth_OpenID_CheckIDRequest::make($query,
                                   $values['identity'],
                                   $values['return_to'],
                                   Auth_OpenID::arrayGet($values,
                                                         'trust_root', null),
                                   $immediate);

        if (Auth_OpenID::arrayGet($values, 'assoc_handle')) {
            $obj->assoc_handle = $values['assoc_handle'];
        }

        return $obj;
    }

    function trustRootValid()
    {
        if (!$this->trust_root) {
            return true;
        }

        $tr = Auth_OpenID_TrustRoot::_parse($this->trust_root);
        if ($tr === false) {
            return new Auth_OpenID_MalformedTrustRoot(null, $this->trust_root);
        }

        return Auth_OpenID_TrustRoot::match($this->trust_root,
                                            $this->return_to);
    }

    function answer($allow, $server_url = null)
    {
        if ($allow || $this->immediate) {
            $mode = 'id_res';
        } else {
            $mode = 'cancel';
        }

        $response = new Auth_OpenID_CheckIDResponse($this, $mode);

        if ($allow) {
            $response->fields['identity'] = $this->identity;
            $response->fields['return_to'] = $this->return_to;
            if (!$this->trustRootValid()) {
                return new Auth_OpenID_UntrustedReturnURL($this->return_to,
                                                          $this->trust_root);
            }
        } else {
            $response->signed = array();
            if ($this->immediate) {
                if (!$server_url) {
                    return new Auth_OpenID_ServerError(null,
                                 'setup_url is required for $allow=false \
                                  in immediate mode.');
                }

                $setup_request =& new Auth_OpenID_CheckIDRequest(
                                                $this->identity,
                                                $this->return_to,
                                                $this->trust_root,
                                                false,
                                                $this->assoc_handle);

                $setup_url = $setup_request->encodeToURL($server_url);

                $response->fields['user_setup_url'] = $setup_url;
            }
        }

        return $response;
    }

    function encodeToURL($server_url)
    {
        global $_Auth_OpenID_OpenID_Prefix;

        // Imported from the alternate reality where these classes are
        // used in both the client and server code, so Requests are
        // Encodable too.  That's right, code imported from alternate
        // realities all for the love of you, id_res/user_setup_url.

        $q = array('mode' => $this->mode,
                   'identity' => $this->identity,
                   'return_to' => $this->return_to);

        if ($this->trust_root) {
            $q['trust_root'] = $this->trust_root;
        }

        if ($this->assoc_handle) {
            $q['assoc_handle'] = $this->assoc_handle;
        }

        $_q = array();

        foreach ($q as $k => $v) {
            $_q[$_Auth_OpenID_OpenID_Prefix . $k] = $v;
        }

        return Auth_OpenID::appendArgs($server_url, $_q);
    }

    function getCancelURL()
    {
        global $_Auth_OpenID_OpenID_Prefix;

        if ($this->immediate) {
            return new Auth_OpenID_ServerError(null,
                                               "Cancel is not an appropriate \
                                               response to immediate mode \
                                               requests.");
        }

        return Auth_OpenID::appendArgs($this->return_to,
                              array($_Auth_OpenID_OpenID_Prefix . 'mode' =>
                                    'cancel'));
    }
}

class Auth_OpenID_ServerResponse {

    function Auth_OpenID_ServerResponse($request)
    {
        $this->request = $request;
        $this->fields = array();
    }

    function whichEncoding()
    {
        global $_Auth_OpenID_Encode_Kvform,
            $_Auth_OpenID_Request_Modes,
            $_Auth_OpenID_Encode_Url;

        if (in_array($this->request->mode, $_Auth_OpenID_Request_Modes)) {
            return $_Auth_OpenID_Encode_Url;
        } else {
            return $_Auth_OpenID_Encode_Kvform;
        }
    }

    function encodeToURL()
    {
        global $_Auth_OpenID_OpenID_Prefix;

        $fields = array();

        foreach ($this->fields as $k => $v) {
            $fields[$_Auth_OpenID_OpenID_Prefix . $k] = $v;
        }

        return Auth_OpenID::appendArgs($this->request->return_to, $fields);
    }

    function encodeToKVForm()
    {
        return Auth_OpenID_KVForm::fromArray($this->fields);
    }
}

class Auth_OpenID_CheckIDResponse extends Auth_OpenID_ServerResponse {

    function Auth_OpenID_CheckIDResponse(&$request, $mode = 'id_res')
    {
        parent::Auth_OpenID_ServerResponse(&$request);
        $this->fields['mode'] = $mode;
        $this->signed = array();

        if ($mode == 'id_res') {
            array_push($this->signed, 'mode', 'identity', 'return_to');
        }
    }

    function addField($namespace, $key, $value, $signed = true)
    {
        if ($namespace) {
            $key = sprintf('%s.%s', $namespace, $key);
        }
        $this->fields[$key] = $value;
        if ($signed && !in_array($key, $this->signed)) {
            $this->signed[] = $key;
        }
    }

    function addFields($namespace, $fields, $signed = true)
    {
        foreach ($fields as $k => $v) {
            $this->addField($namespace, $k, $v, $signed);
        }
    }

    function update($namespace, $other)
    {
        $namespaced_fields = array();

        foreach ($other->fields as $k => $v) {
            $name = sprintf('%s.%s', $namespace, $k);

            $namespaced_fields[$name] = $v;
        }

        $this->fields = array_merge($this->fields, $namespaced_fields);
        $this->signed = array_merge($this->signed, $other->signed);
    }
}

class Auth_OpenID_WebResponse {
    var $code = AUTH_OPENID_HTTP_OK;
    var $body = "";

    function Auth_OpenID_WebResponse($code = null, $headers = null,
                                     $body = null)
    {
        if ($code) {
            $this->code = $code;
        }

        if ($headers !== null) {
            $this->headers = $headers;
        } else {
            $this->headers = array();
        }

        if ($body !== null) {
            $this->body = $body;
        }
    }
}

class Auth_OpenID_Signatory {

    // = 14 * 24 * 60 * 60; # 14 days, in seconds
    var $SECRET_LIFETIME = 1209600;

    // keys have a bogus server URL in them because the filestore
    // really does expect that key to be a URL.  This seems a little
    // silly for the server store, since I expect there to be only one
    // server URL.
    var $normal_key = 'http://localhost/|normal';
    var $dumb_key = 'http://localhost/|dumb';

    function Auth_OpenID_Signatory(&$store)
    {
        // assert store is not None
        $this->store =& $store;
    }

    function verify($assoc_handle, $sig, $signed_pairs)
    {
        $assoc = $this->getAssociation($assoc_handle, true);
        if (!$assoc) {
            // oidutil.log("failed to get assoc with handle %r to verify sig %r"
            //             % (assoc_handle, sig))
            return false;
        }

        $expected_sig = base64_encode($assoc->sign($signed_pairs));

        return $sig == $expected_sig;
    }

    function sign($response)
    {
        $signed_response = $response;
        $assoc_handle = $response->request->assoc_handle;

        if ($assoc_handle) {
            // normal mode
            $assoc = $this->getAssociation($assoc_handle, false);
            if (!$assoc) {
                // fall back to dumb mode
                $signed_response->fields['invalidate_handle'] = $assoc_handle;
                $assoc = $this->createAssociation(true);
            }
        } else {
            // dumb mode.
            $assoc = $this->createAssociation(true);
        }

        $signed_response->fields['assoc_handle'] = $assoc->handle;
        $assoc->addSignature($signed_response->signed,
                             $signed_response->fields, '');
        return $signed_response;
    }

    function createAssociation($dumb = true, $assoc_type = 'HMAC-SHA1')
    {
        $secret = Auth_OpenID_CryptUtil::getBytes(20);
        $uniq = base64_encode(Auth_OpenID_CryptUtil::getBytes(4));
        $handle = sprintf('{%s}{%x}{%s}', $assoc_type, intval(time()), $uniq);

        $assoc = Auth_OpenID_Association::fromExpiresIn(
                      $this->SECRET_LIFETIME, $handle, $secret, $assoc_type);

        if ($dumb) {
            $key = $this->dumb_key;
        } else {
            $key = $this->normal_key;
        }

        $this->store->storeAssociation($key, $assoc);
        return $assoc;
    }

    function getAssociation($assoc_handle, $dumb)
    {
        if ($assoc_handle === null) {
            return new Auth_OpenID_ServerError(null,
                                     "assoc_handle must not be null");
        }

        if ($dumb) {
            $key = $this->dumb_key;
        } else {
            $key = $this->normal_key;
        }

        $assoc = $this->store->getAssociation($key, $assoc_handle);

        if (($assoc !== null) && ($assoc->getExpiresIn() <= 0)) {
            $this->store->removeAssociation($key, $assoc_handle);
            $assoc = null;
        }

        return $assoc;
    }

    function invalidate($assoc_handle, $dumb)
    {
        if ($dumb) {
            $key = $this->dumb_key;
        } else {
            $key = $this->normal_key;
        }
        $this->store->removeAssociation($key, $assoc_handle);
    }
}

class Auth_OpenID_Encoder {

    var $responseFactory = 'Auth_OpenID_WebResponse';

    function encode(&$response)
    {
        global $_Auth_OpenID_Encode_Kvform,
            $_Auth_OpenID_Encode_Url;

        $cls = $this->responseFactory;

        $encode_as = $response->whichEncoding();
        if ($encode_as == $_Auth_OpenID_Encode_Kvform) {
            $wr = new $cls(null, null, $response->encodeToKVForm());
            if (is_a($response, 'Auth_OpenID_ServerError')) {
                $wr->code = AUTH_OPENID_HTTP_ERROR;
            }
        } else if ($encode_as == $_Auth_OpenID_Encode_Url) {
            $location = $response->encodeToURL();
            $wr = new $cls(AUTH_OPENID_HTTP_REDIRECT,
                           array('location' => $location));
        } else {
            return new Auth_OpenID_EncodingError(&$response);
        }
        return $wr;
    }
}

function needsSigning($response)
{
    return (in_array($response->request->mode, array('checkid_setup',
                                                     'checkid_immediate')) &&
            $response->signed);
}

class Auth_OpenID_SigningEncoder extends Auth_OpenID_Encoder {

    function Auth_OpenID_SigningEncoder(&$signatory)
    {
        $this->signatory =& $signatory;
    }

    function encode(&$response)
    {
        // the isinstance is a bit of a kludge... it means there isn't
        // really an adapter to make the interfaces quite match.
        if (!is_a($response, 'Auth_OpenID_ServerError') &&
            needsSigning($response)) {

            if (!$this->signatory) {
                return new Auth_OpenID_ServerError(null,
                                       "Must have a store to sign request");
            }
            if (array_key_exists('sig', $response->fields)) {
                return new Auth_OpenID_AlreadySigned($response);
            }
            $response = $this->signatory->sign($response);
        }
        return parent::encode($response);
    }
}

class Auth_OpenID_Decoder {

    function Auth_OpenID_Decoder()
    {
        global $_Auth_OpenID_OpenID_Prefix;
        $this->prefix = $_Auth_OpenID_OpenID_Prefix;

        $this->handlers = array(
            'checkid_setup' => 'Auth_OpenID_CheckIDRequest',
            'checkid_immediate' => 'Auth_OpenID_CheckIDRequest',
            'check_authentication' => 'Auth_OpenID_CheckAuthRequest',
            'associate' => 'Auth_OpenID_AssociateRequest'
            );
    }

    function decode($query)
    {
        if (!$query) {
            return null;
        }

        $myquery = array();

        foreach ($query as $k => $v) {
            if (strpos($k, $this->prefix) === 0) {
                $myquery[$k] = $v;
            }
        }

        if (!$myquery) {
            return null;
        }

        $mode = Auth_OpenID::arrayGet($myquery, $this->prefix . 'mode');
        if (!$mode) {
            return new Auth_OpenID_ServerError($query,
                           sprintf("No %smode found in query", $this->prefix));
        }

        $handlerCls = Auth_OpenID::arrayGet($this->handlers, $mode,
                                            $this->defaultDecoder($query));

        if (!is_a($handlerCls, 'Auth_OpenID_ServerError')) {
            return call_user_func_array(array($handlerCls, 'fromQuery'),
                                        array($query));
        } else {
            return $handlerCls;
        }
    }

    function defaultDecoder($query)
    {
        $mode = $query[$this->prefix . 'mode'];
        return new Auth_OpenID_ServerError($query,
                       sprintf("No decoder for mode %s", $mode));
    }
}

class Auth_OpenID_EncodingError {
    function Auth_OpenID_EncodingError(&$response)
    {
        $this->response =& $response;
    }
}

class Auth_OpenID_AlreadySigned extends Auth_OpenID_EncodingError {
    // This response is already signed.
}

class Auth_OpenID_UntrustedReturnURL extends Auth_OpenID_ServerError {
    function Auth_OpenID_UntrustedReturnURL($return_to, $trust_root)
    {
        $this->return_to = $return_to;
        $this->trust_root = $trust_root;
    }

    function toString()
    {
        return sprintf("return_to %s not under trust_root %s", $this->return_to,
                       $this->trust_root);
    }
}

/**
 * An object that implements the OpenID protocol for a single URL.
 *
 * Use this object by calling getOpenIDResponse when you get any
 * request for the server URL.
 *
 * @package OpenID
 */
class Auth_OpenID_Server {
    function Auth_OpenID_Server(&$store)
    {
        $this->store =& $store;
        $this->signatory =& new Auth_OpenID_Signatory($this->store);
        $this->encoder =& new Auth_OpenID_SigningEncoder($this->signatory);
        $this->decoder =& new Auth_OpenID_Decoder();
    }

    function handleRequest($request)
    {
        if (method_exists($this, "openid_" . $request->mode)) {
            $handler = "openid_" . $request->mode;
            return $handler($request);
        }
        return null;
    }

    function openid_check_authentication(&$request)
    {
        return $request->answer($this->signatory);
    }

    function openid_associate(&$request)
    {
        $assoc = $this->signatory->createAssociation(false);
        return $request->answer($assoc);
    }

    function encodeResponse(&$response)
    {
        return $this->encoder->encode($response);
    }

    function decodeRequest(&$query)
    {
        return $this->decoder->decode($query);
    }
}

?>
