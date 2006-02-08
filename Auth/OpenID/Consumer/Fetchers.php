<?php

/**
 * This module contains the HTTP fetcher interface and several
 * implementations.
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
 * Specify a socket timeout setting, in seconds.
 */
$_Auth_OpenID_socket_timeout = 20;

/**
 * Is this an http or https URL?
 *
 * @access private
 */
function Auth_OpenID_URLHasAllowedScheme($url)
{
    return (bool)preg_match('/^https?:\/\//i', $url);
}

/**
 * This class is the interface for HTTP fetchers the OpenID consumer
 * library uses.  This interface is only important if you need to
 * write a new fetcher for some reason.
 *
 * @access private
 * @package OpenID
 */
class Auth_OpenID_HTTPFetcher {

    /**
     * Return whether a URL should be allowed. Override this method to
     * conform to your local policy.
     *
     * By default, will attempt to fetch any http or https URL.
     */
    function allowedURL($url)
    {
        return Auth_OpenID_URLHasAllowedScheme($url);
    }

    /**
     * This performs an HTTP get, following redirects along the way.
     *
     * @return array $tuple This returns a three-tuple on success.
     * The first value is the http return code. The second value is
     * the final url that was fetched, after following any redirects.
     * The third value is the data that was retrieved from the site.
     * If the fetch didn't succeed, return null.
    */
    function get($url)
    {
        trigger_error("not implemented", E_USER_ERROR);
    }

    /**
     * This performs an HTTP post.  If it makes sense, it will follow
     * redirects along the way.
     *
     * @return array $tuple This returns a three-tuple on success.
     * The first value is the http return code. The second value is
     * the final url that was fetched, after following any redirects.
     * The third value is the data that was retrieved from the site.
     * If the fetch didn't succeed, return null.
     */
    function post($url, $body)
    {
        trigger_error("not implemented", E_USER_ERROR);
    }
}

/**
 * Detect the presence of Curl and set a flag accordingly.
 */
define('Auth_OpenID_CURL_PRESENT', function_exists('curl_init'));

function Auth_OpenID_getHTTPFetcher()
{
    if (Auth_OpenID_CURL_PRESENT) {
        $fetcher = new Auth_OpenID_ParanoidHTTPFetcher();
    } else {
        $fetcher = new Auth_OpenID_PlainHTTPFetcher();
    }

    return $fetcher;
}

/**
 * This class implements a plain, hand-built socket-based fetcher
 * which will be used in the event that CURL is unavailable.
 *
 * @package OpenID
 */
class Auth_OpenID_PlainHTTPFetcher extends Auth_OpenID_HTTPFetcher {
    /**
     * @access private
     */
    function _fetch($url)
    {
        $data = @file_get_contents($url);

        if ($data !== false) {
            return array(200, $url, $data);
        } else {
            return null;
        }
    }

    function get($url)
    {
        if (!$this->allowedURL($url)) {
            trigger_error("Bad URL scheme in url: " . $url,
                          E_USER_WARNING);
            return null;
        }

        return $this->_fetch($url);
    }

    function post($url, $body)
    {
        global $_Auth_OpenID_socket_timeout;

        if (!$this->allowedURL($url)) {
            trigger_error("Bad URL scheme in url: " . $url,
                          E_USER_WARNING);
            return null;
        }

        $parts = parse_url($url);

        $headers = array();

        $headers[] = "POST ".$parts['path']." HTTP/1.1";
        $headers[] = "Host: " . $parts['host'];
        $headers[] = "Content-type: application/x-www-form-urlencoded";
        $headers[] = "Content-length: " . strval(strlen($body));

        // Join all headers together.
        $all_headers = implode("\r\n", $headers);

        // Add headers, two newlines, and request body.
        $request = $all_headers . "\r\n\r\n" . $body;

        // Set a default port.
        if (!array_key_exists('port', $parts)) {
            if ($parts['scheme'] == 'http') {
                $parts['port'] = 80;
            } elseif ($parts['scheme'] == 'https') {
                $parts['port'] = 443;
            } else {
                trigger_error("fetcher post method doesn't support scheme '" .
                              $parts['scheme'] .
                              "', no default port available",
                              E_USER_WARNING);
                return null;
            }
        }

        if ($parts['scheme'] == 'https') {
            $parts['host'] = sprintf("ssl://%s", $parts['host']);
        }

        // Connect to the remote server.
        $sock = fsockopen($parts['host'], $parts['port']);
        stream_set_timeout($sock, $_Auth_OpenID_socket_timeout);

        if ($sock === false) {
            trigger_error("Could not connect to " . $parts['host'] .
                          " port " . $parts['port'],
                          E_USER_WARNING);
            return null;
        }

        // Write the POST request.
        fputs($sock, $request);

        // Get the response from the server.
        $response = "";
        while (!feof($sock)) {
            if ($data = fgets($sock, 128)) {
                $response .= $data;
            } else {
                break;
            }
        }

        // Split the request into headers and body.
        list($headers, $response_body) = explode("\r\n\r\n", $response, 2);

        $headers = explode("\r\n", $headers);

        // Expect the first line of the headers data to be something
        // like HTTP/1.1 200 OK.  Split the line on spaces and take
        // the second token, which should be the return code.
        $http_code = explode(" ", $headers[0]);
        $code = $http_code[1];

        return array($code, $url, $response_body);
    }
}

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

    /**
     * @access private
     */
    function _findRedirect($headers)
    {
        foreach ($headers as $line) {
            if (strpos($line, "Location: ") == 0) {
                $parts = explode(" ", $line, 2);
                return $parts[1];
            }
        }
        return null;
    }

    function get($url)
    {
        global $_Auth_OpenID_socket_timeout;
        global $_Auth_OpenID_curl_data;

        $c = curl_init();

        $curl_key = Auth_OpenID_initResponseSlot($c);

        curl_setopt($c, CURLOPT_NOSIGNAL, true);

        $stop = time() + $_Auth_OpenID_socket_timeout;
        $off = $_Auth_OpenID_socket_timeout;

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
        global $_Auth_OpenID_socket_timeout;
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
        curl_setopt($c, CURLOPT_TIMEOUT, $_Auth_OpenID_socket_timeout);
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