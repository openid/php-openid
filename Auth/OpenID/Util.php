<?php

/**
 * Util: URL manipulation utility functions for the OpenID library.
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
 *
 * @access private
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
 * @access private
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
 * @access private
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