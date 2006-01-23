<?php

/**
 * OIDUtil: URL manipulation utility functions for the OpenID library.
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
 * Some constants for string checking.
 */
$_Auth_OpenID_letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
$_Auth_OpenID_digits = "0123456789";
$_Auth_OpenID_punct = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

/**
 * Create dir_name as a directory if it does not exist. If it exists,
 * make sure that it is, in fact, a directory.  Returns true if the
 * operation succeeded; false if not.
 */
function ensureDir($dir_name)
{
    if (@mkdir($dir_name) || is_dir($dir_name)) {
        return true;
    } else {
        return false;
    }
}

/**
 * Convenience function for getting array values.
 */
function Auth_OpenID_array_get($arr, $key, $fallback = null)
{
    if (is_array($arr)) {
        if (array_key_exists($key, $arr)) {
            return $arr[$key];
        } else {
            return $fallback;
        }
    } else {
        trigger_error("Auth_OpenID_array_get expected " .
                      "array as first parameter", E_USER_WARNING);
        return false;
    }
}


/**
 * Prints the specified message using trigger_error(E_USER_NOTICE).
 */
function Auth_OpenID_log($message, $unused_level = 0)
{
    trigger_error($message, E_USER_NOTICE);
}

/**
 * Rename specified query arguments back to 'openid.' from 'openid_'
 *
 * @param array $args An associative array of URL query arguments
 *
 * @param array $allowed A set of strings indicating which 'openid_'
 *    keys should be renamed.
 */
function Auth_OpenID_fixArgs(&$args, $allowed)
{
    foreach ($allowed as $key_ext) {
        $key = 'openid_' . $key_ext;
        if (isset($args[$key])) {
            $val = $args[$key];
            unset($args[$key]);
            $args['openid.' . $key_ext] = $val;
        }
    }
}

/**
 * Implements the PHP 5 'http_build_query' functionality.
 *
 * @param array $data Either an array key/value pairs or an array of
 * arrays, each of which holding two values: a key and a value,
 * sequentially.
 * @return string $result The result of url-encoding the key/value
 * pairs from $data into a URL query string
 * (e.g. "username=bob&id=56").
 */
function Auth_OpenID_http_build_query($data)
{
    $pairs = array();
    foreach ($data as $key => $value) {
        if (is_array($value)) {
            $pairs[] = urlencode($value[0])."=".urlencode($value[1]);
        } else {
            $pairs[] = urlencode($key)."=".urlencode($value);
        }
    }
    return implode("&", $pairs);
}

/**
 * "Appends" query arguments onto a URL.  The URL may or may not
 * already have arguments (following a question mark).
 *
 * @param string $url A URL, which may or may not already have
 * arguments.
 * @param array $args Either an array key/value pairs or an array of
 * arrays, each of which holding two values: a key and a value,
 * sequentially.  If $args is an ordinary key/value array, the
 * parameters will be added to the URL in sorted alphabetical order;
 * if $args is an array of arrays, their order will be preserved.
 * @return string $url The original URL with the new parameters added.
 *
 */
function Auth_OpenID_appendArgs($url, $args)
{

    if (count($args) == 0) {
        return $url;
    }

    // Non-empty array; if it is an array of arrays, use multisort;
    // otherwise use sort.
    if (array_key_exists(0, $args) &&
        is_array($args[0])) {
        // Do nothing here.
    } else {
        $keys = array_keys($args);
        sort($keys);
        $new_args = array();
        foreach ($keys as $key) {
            $new_args[] = array($key, $args[$key]);
        }
        $args = $new_args;
    }

    $sep = '?';
    if (strpos($url, '?') !== false) {
        $sep = '&';
    }

    return $url . $sep . Auth_OpenID_http_build_query($args);
}

/**
 * Turn a string into an ASCII string.
 *
 * Replace non-ascii characters with a %-encoded, UTF-8 encoding. This
 * function will fail if the input is a string and there are
 * non-7-bit-safe characters. It is assumed that the caller will have
 * already translated the input into a Unicode character sequence,
 * according to the encoding of the HTTP POST or GET.
 *
 * Do not escape anything that is already 7-bit safe, so we do the
 * minimal transform on the identity URL
 */
function Auth_OpenID_quoteMinimal($s)
{
    $res = array();
    for ($i = 0; $i < strlen($s); $i++) {
        $c = $s[$i];
        if ($c >= "\x80") {
            for ($j = 0; $j < count(utf8_encode($c)); $j++) {
                array_push($res, sprintf("%02X", ord($c[$j])));
            }
        } else {
            array_push($res, $c);
        }
    }
    
    return implode('', $res);
}

/**
 * Implements python's urlunparse, which is not available in PHP.
 * Given the specified components of a URL, this function rebuilds and
 * returns the URL.
 *
 * @param string $scheme The scheme (e.g. 'http').  Defaults to 'http'.
 * @param string $host The host.  Required.
 * @param string $port The port.
 * @param string $path The path.
 * @param string $query The query.
 * @param string $fragment The fragment.
 * @return string $url The URL resulting from assembling the specified
 * components.
 */
function Auth_OpenID_urlunparse($scheme, $host, $port = null, $path = '/',
                               $query = '', $fragment = '')
{

    if (!$scheme) {
        $scheme = 'http';
    }

    if (!$host) {
        return false;
    }

    if (!$path) {
        $path = '/';
    }

    $result = $scheme . "://" . $host;

    if ($port) {
        $result .= ":" . $port;
    }

    $result .= $path;

    if ($query) {
        $result .= "?" . $query;
    }

    if ($fragment) {
        $result .= "#" . $fragment;
    }

    return $result;
}

/**
 * Given a URL, this "normalizes" it by adding a trailing slash and /
 * or a leading http:// scheme where necessary.  Returns null if the
 * original URL is malformed and cannot be normalized.
 *
 * @param string $url The URL to be normalized.
 * @return mixed $new_url The URL after normalization, or null if $url
 * was malformed.
 */
function Auth_OpenID_normalizeUrl($url)
{
    if ($url === null) {
        return null;
    }

    assert(is_string($url));

    $old_url = $url;
    $url = trim($url);

    if (strpos($url, "://") === false) {
        $url = "http://" . $url;
    }

    $parsed = @parse_url($url);

    if ($parsed === false) {
        return null;
    }

    $defaults = array(
                      'scheme' => '',
                      'host' => '',
                      'path' => '',
                      'query' => '',
                      'fragment' => '',
                      'port' => ''
                      );

    $parsed = array_merge($defaults, $parsed);

    if (($parsed['scheme'] == '') ||
        ($parsed['host'] == '')) {
        if ($parsed['path'] == '' &&
            $parsed['query'] == '' &&
            $parsed['fragment'] == '') {
            return null;
        }

        $url = 'http://' + $url;
        $parsed = parse_url($url);

        $parsed = array_merge($defaults, $parsed);
    }

    $tail = array_map('Auth_OpenID_quoteMinimal', array($parsed['path'],
                                                       $parsed['query'],
                                                       $parsed['fragment']));
    if ($tail[0] == '') {
        $tail[0] = '/';
    }

    $url = Auth_OpenID_urlunparse($parsed['scheme'], $parsed['host'],
                                 $parsed['port'], $tail[0], $tail[1],
                                 $tail[2]);

    assert(is_string($url));

    return $url;
}

?>