<?php

function Net_OpenID_log($message, $unused_level = 0) {
    trigger_error($message, E_USER_NOTICE);
}

function Net_OpenID_appendArgs($url, $args) {
    /*
    if (is_array($args)) {
        $args = $args->items();
        $args->sort();
    }
    */

    if (count($args) == 0) {
        return $url;
    }

    $sep = '?';
    if (strpos($url, '?') !== false) {
        $sep = '&';
    }

    return $url . $sep . http_build_query($args);
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

function urlunparse($scheme, $host, $port, $path, $query, $fragment) {

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

function normalizeUrl($url) {
    if ($url === null) {
        return null;
    }

    assert(is_string($url));

    $url = strip($url);
    $parsed = urlparse($url);

    if (($parsed['scheme'] == '') ||
        ($parsed['host'] == '')) {
        if ($parsed['path'] == '' &&
            $parsed['query'] == '' &&
            $parsed['fragment'] == '') {
            return null;
        }

        $url = 'http://' + $url;
        $parsed = parse_url($url);
    }

    $tail = array_map(Net_OpenID_quoteMinimal, array($parsed['path'],
                                                     $parsed['query'], $parsed['fragment']));
    if ($tail[0] == '') {
        $tail[0] = '/';
    }

    $url = urlunparse($parsed[0], $parsed['host'], $parsed['port'],
                      $tail[0], $tail[1], $tail[2]);

    assert(is_string($url));

    return $url;
}

?>