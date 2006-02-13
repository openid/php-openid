<?php

/**
 * This module contains the CURL-based HTTP fetcher implementation.
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
 * Interface import
 */
require_once "Auth/OpenID/HTTPFetcher.php";

/**
 * Define this based on whether the CURL extension is available.
 */
define('Auth_OpenID_CURL_PRESENT', function_exists('curl_init'));

/**
 * An array to store headers and data from Curl calls.
 *
 * @access private
 */
$_Auth_OpenID_curl_data = array();

/**
 * A function to prepare a "slot" in the global $_Auth_OpenID_curl_data
 * array so curl data can be stored there by curl callbacks in the
 * paranoid fetcher.
 *
 * @access private
 */
function Auth_OpenID_initResponseSlot($ch)
{
    global $_Auth_OpenID_curl_data;
    $key = strval($ch);
    if (!array_key_exists($key, $_Auth_OpenID_curl_data)) {
        $_Auth_OpenID_curl_data[$key] = array('headers' => array(),
                                             'body' => "");
    }
    return $key;
}

/**
 * A callback function for curl so headers can be stored.
 *
 * @access private
 */
function Auth_OpenID_writeHeaders($ch, $data)
{
    global $_Auth_OpenID_curl_data;
    $key = Auth_OpenID_initResponseSlot($ch);
    $_Auth_OpenID_curl_data[$key]['headers'][] = rtrim($data);
    return strlen($data);
}

/**
 * A callback function for curl so page data can be stored.
 *
 * @access private
 */
function Auth_OpenID_writeData($ch, $data)
{
    global $_Auth_OpenID_curl_data;
    $key = Auth_OpenID_initResponseSlot($ch);
    $_Auth_OpenID_curl_data[$key]['body'] .= $data;
    return strlen($data);
}

/**
 * A paranoid Auth_OpenID_HTTPFetcher class which uses CURL for
 * fetching.
 *
 * @package OpenID
 */
class Auth_OpenID_ParanoidHTTPFetcher extends Auth_OpenID_HTTPFetcher {
    function Auth_OpenID_ParanoidHTTPFetcher()
    {
        if (!Auth_OpenID_CURL_PRESENT) {
            trigger_error("Cannot use this class; CURL extension not found",
                          E_USER_ERROR);
        }
    }

    function get($url)
    {
        global $_Auth_OpenID_curl_data;

        $c = curl_init();

        $curl_key = Auth_OpenID_initResponseSlot($c);

        curl_setopt($c, CURLOPT_NOSIGNAL, true);

        $stop = time() + $this->timeout;
        $off = $this->timeout;

        while ($off > 0) {
            if (!$this->allowedURL($url)) {
                trigger_error(sprintf("Fetching URL not allowed: %s", $url),
                              E_USER_WARNING);
                return null;
            }

            curl_setopt($c, CURLOPT_WRITEFUNCTION, "Auth_OpenID_writeData");
            curl_setopt($c, CURLOPT_HEADERFUNCTION, "Auth_OpenID_writeHeaders");
            curl_setopt($c, CURLOPT_TIMEOUT, $off);
            curl_setopt($c, CURLOPT_URL, $url);

            curl_exec($c);

            $code = curl_getinfo($c, CURLINFO_HTTP_CODE);
            $body = $_Auth_OpenID_curl_data[$curl_key]['body'];
            $headers = $_Auth_OpenID_curl_data[$curl_key]['headers'];

            if (!$code) {
                trigger_error("No HTTP code returned", E_USER_WARNING);
                return null;
            }

            if (in_array($code, array(301, 302, 303, 307))) {
                $url = $this->_findRedirect($headers);
            } else {
                curl_close($c);
                return array($code, $url, $body);
            }

            $off = $stop - time();
        }

        trigger_error(sprintf("Timed out fetching: %s", $url),
                      E_USER_WARNING);

        return null;
    }

    function post($url, $body)
    {
        global $_Auth_OpenID_curl_data;

        if (!$this->allowedURL($url)) {
            trigger_error(sprintf("Fetching URL not allowed: %s", $url),
                          E_USER_WARNING);
            return null;
        }

        $c = curl_init();

        $curl_key = Auth_OpenID_initResponseSlot($c);

        curl_setopt($c, CURLOPT_NOSIGNAL, true);
        curl_setopt($c, CURLOPT_POST, true);
        curl_setopt($c, CURLOPT_POSTFIELDS, $body);
        curl_setopt($c, CURLOPT_TIMEOUT, $this->timeout);
        curl_setopt($c, CURLOPT_URL, $url);
        curl_setopt($c, CURLOPT_WRITEFUNCTION, "Auth_OpenID_writeData");

        curl_exec($c);

        $code = curl_getinfo($c, CURLINFO_HTTP_CODE);

        if (!$code) {
            trigger_error("No HTTP code returned", E_USER_WARNING);
            return null;
        }

        $body = $_Auth_OpenID_curl_data[$curl_key]['body'];

        curl_close($c);
        return array($code, $url, $body);
    }
}

?>