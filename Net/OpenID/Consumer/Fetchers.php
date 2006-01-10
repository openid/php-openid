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
 * Specify a socket timeout setting (in seconds).
 */
$_Net_OpenID_socket_timeout = 20;

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

class Net_OpenID_PlainFetcher extends Net_OpenID_HTTPFetcher {
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
        global $_Net_OpenID_socket_timeout;

        if (!Net_OpenID_allowedURL($url)) {
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
        $all_headers = implode("\n", $headers);

        // Add headers, two newlines, and request body.
        $request = $all_headers . "\n\n" . $body;

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

        // Connect to the remote server.
        $sock = fsockopen($parts['host'], $parts['port']);
        stream_set_timeout($sock, $_Net_OpenID_socket_timeout);

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
        list($headers, $response_body) = explode("\n\n", $response, 2);

        $headers = explode("\n", $headers);

        // Expect the first line of the headers data to be something
        // like HTTP/1.1 200 OK.  Split the line on spaces and take
        // the second token, which should be the return code.
        $http_code = explode(" ", $headers[0]);
        $code = $http_code[1];

        return array($code, $url, $response_body);
    }
}

?>