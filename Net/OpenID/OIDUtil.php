<?php

function Net_OpenID_log($message, $unused_level = 0) {
    trigger_error($message, E_USER_NOTICE);
}

// 'http_build_query' is provided in PHP 5, but not in 4.
function Net_OpenID_http_build_query($data) {
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

function Net_OpenID_appendArgs($url, $args) {

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

    return $url . $sep . Net_OpenID_http_build_query($args);
}

function Net_OpenID_toBase64($s) {
    return base64_encode($s);
}

function Net_OpenID_fromBase64($s) {
    return base64_decode($s);
}

/**
 * Turn a string into an ASCII string
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
function Net_OpenID_quoteMinimal($s) {
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

function Net_OpenID_urlunparse($scheme, $host, $port, $path, $query, $fragment) {

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

function Net_OpenID_normalizeUrl($url) {
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

    $tail = array_map('Net_OpenID_quoteMinimal', array($parsed['path'],
                                                       $parsed['query'], $parsed['fragment']));
    if ($tail[0] == '') {
        $tail[0] = '/';
    }

    $url = Net_OpenID_urlunparse($parsed['scheme'], $parsed['host'], $parsed['port'],
                                 $tail[0], $tail[1], $tail[2]);

    assert(is_string($url));

    return $url;
}

?>