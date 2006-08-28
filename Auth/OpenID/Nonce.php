<?php

/**
 * Nonce-related functionality.
 */

require_once 'Auth/OpenID/CryptUtil.php';

/**
 * This is the characters that the nonces are made from.
 */
define('Auth_OpenID_DEFAULT_NONCE_CHRS',"abcdefghijklmnopqrstuvwxyz" .
       "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");

// Keep nonces for five hours (allow five hours for the combination of
// request time and clock skew). This is probably way more than is
// necessary, but there is not much overhead in storing nonces.
$Auth_OpenID_SKEW = 60 * 60 * 5;

$Auth_OpenID_time_fmt = '%Y-%m-%dT%H:%M:%SZ';
$Auth_OpenID_time_str_len = strlen('0000-00-00T00:00:00Z');

function Auth_OpenID_splitNonce($nonce_string)
{
    // Extract a timestamp from the given nonce string
    global $Auth_OpenID_time_fmt,
        $Auth_OpenID_time_str_len;

    $timestamp_str = substr($nonce_string, 0, $Auth_OpenID_time_str_len);
    $parts = strptime($timestamp_str, $Auth_OpenID_time_fmt);

    $timestamp = gmmktime($parts['tm_hour'], $parts['tm_min'],
                          $parts['tm_sec'], $parts['tm_mon'] + 1,
                          $parts['tm_mday'], $parts['tm_year'] + 1900);

    return array($timestamp, substr($nonce_string, $Auth_OpenID_time_str_len));
}

function Auth_OpenID_checkTimestamp($nonce_string,
                                    $allowed_skew = null,
                                    $now = null)
{
    // Is the timestamp that is part of the specified nonce string
    // within the allowed clock-skew of the current time?
    global $Auth_OpenID_SKEW;

    if ($allowed_skew === null) {
        $allowed_skew = $Auth_OpenID_SKEW;
    }

    $parts = explode($nonce_string, 2);
    if (count($parts) != 2) {
        return false;
    } else {
        if ($now === null) {
            $now = time();
        }

        // Time after which we should not use the nonce
        $past = $now - $allowed_skew;

        // Time that is too far in the future for us to allow
        $future = $now + $allowed_skew;

        // the stamp is not too far in the future and is not too far
        // in the past
        return (($past < $stamp) && ($stamp < $future));
    }
}

function Auth_OpenID_mkNonce($when = null)
{
    global $Auth_OpenID_time_fmt;

    // Generate a nonce with the current timestamp
    $salt = Auth_OpenID_CryptUtil::randomString(6,
                                Auth_OpenID_DEFAULT_NONCE_CHRS);
    if ($when === null) {
        $when = gmmktime();
    }

    $time_str = gmstrftime($Auth_OpenID_time_fmt, $when);
    return $time_str . $salt;
}

?>