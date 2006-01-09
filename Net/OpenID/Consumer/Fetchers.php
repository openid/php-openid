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

class Net_OpenID_HTTPFetcher {
    /**
     * This class is the interface for HTTP fetchers the OpenID
     * consumer library uses.  This interface is only important if you
     * need to write a new fetcher for some reason.
     */
    function get($url)
    {
        trigger_error("not implemented", E_USER_ERROR);
    }

    /**
     * This performs an HTTP post.  If it makes sense, it will follow
     * redirects along the way.
     */
    function post($url, $body)
    {
        trigger_error("not implemented", E_USER_ERROR);
    }
}

/**
 * Detect the presence of Curl and set a flag accordingly.
 */
$_Net_OpenID_curl_found = false;
if (function_exists('curl_init')) {
    $_Net_OpenID_curl_found = true;
}

function Net_OpenID_getHTTPFetcher()
{
    global $_Net_OpenID_curl_found;
    if (!$_Net_OpenID_curl_found) {
        $fetcher = new UrllibFetcher();
    } else {
        $fetcher = new ParanoidHTTPFetcher();
    }

    /*
    if (!$raise_errors) {
        $fetcher = ExceptionCatchingFetcher($fetcher);
    }
    */

    return $fetcher;
}

function Net_OpenID_allowedURL($url)
{
    // url.startswith('http://') or url.startswith('https://')
    return (strpos($url, 'http://') == 0) ||
        (strpos($url, 'https://') == 0);
}

class Net_OpenID_PlainFetcher extends Net_OpenID_HTTPFetcher
{
    function _fetch($request)
    {
        $data = file_get_contents();

        if ($data !== false) {
            return array(200, $url, $data);
        } else {
            return null;
        }
    }

    function get($url)
    {
        if (!Net_OpenID_allowedURL($url)) {
            trigger_error("Bad URL scheme in url: " . $url,
                          E_USER_WARNING);
            return null;
        }

        return $this->_fetch($url);
    }

    function post($url, $body)
    {
        if (!Net_OpenID_allowedURL($url)) {
            trigger_error("Bad URL scheme in url: " . $url,
                          E_USER_WARNING);
            return null;
        }

        $parts = parse_url($url);

        $headers = array();

        $headers[] = "POST $url HTTP/1.1";
        $headers[] = "Host: " . $parts['host'];
        $headers[] = "Content-type: application/x-www-form-urlencoded";
        $headers[] = "Content-length: " . strval(strlen($body));

        $all_headers = implode("\n", $headers);

        $request = $all_headers . "\n\n" . $body;

        if (!array_key_exists('port', $parts)) {
            $parts['port'] = 80;
        }

        $sock = fsockopen($parts['host'], $parts['port']);

        if ($sock === false) {
            trigger_error("Could not connect to " . $parts['host'] .
                          " port " . $parts['port'],
                          E_USER_WARNING);
            return null;
        }

        $response = "";
        while (!feof($sock)) {
            $response .= fgets($sock, 1024);
        }

        // Need to separate headers from body.

        return array(200, $url, $response);
    }
}

?>