<?php

/**
 * CryptUtil: A suite of wrapper utility functions for the OpenID
 * library.
 *
 * PHP versions 4 and 5
 *
 * LICENSE: See the COPYING file included in this distribution.
 *
 * @access private
 * @package OpenID
 * @author JanRain, Inc. <openid@janrain.com>
 * @copyright 2005 Janrain, Inc.
 * @license http://www.gnu.org/copyleft/lesser.html LGPL
 */

if (!defined('Auth_OpenID_RAND_SOURCE')) {
    /**
     * The filename for a source of random bytes. Define this yourself
     * if you have a different source of randomness.
     */
    define('Auth_OpenID_RAND_SOURCE', '/dev/urandom');
}

/** 
 * Get the specified number of random bytes.
 *
 * Attempts to use a cryptographically secure (not predictable)
 * source of randomness if available. If there is no high-entropy
 * randomness source available, it will fail. As a last resort,
 * for non-critical systems, define
 * <code>Auth_OpenID_USE_INSECURE_RAND</code>, and the code will
 * fall back on a pseudo-random number generator.
 *
 * @param int $num_bytes The length of the return value
 * @return string $bytes random bytes
 */
function Auth_OpenID_getBytes($num_bytes)
{
    $bytes = '';
    $f = @fopen(Auth_OpenID_RAND_SOURCE, "r");
    if ($f === false) {
        if (!defined('Auth_OpenID_USE_INSECURE_RAND')) {
            $msg = 'Set Auth_OpenID_USE_INSECURE_RAND to continue with an ' .
                'insecure random number generator.';
            trigger_error($msg, E_USER_ERROR);
        }
        $bytes = '';
        for ($i = 0; $i < $num_bytes; $i += 4) {
            $bytes .= pack('L', mt_rand());
        }
        $bytes = substr($bytes, 0, $num_bytes);
    } else {
        $bytes = fread($f, $num_bytes);
        fclose($f);
    }
    return $bytes;
}

/**
 * Produce a string of length random bytes, chosen from chrs.  If
 * $chrs is null, the resulting string may contain any characters.
 *
 * @param integer $length The length of the resulting
 * randomly-generated string
 * @param string $chrs A string of characters from which to choose
 * to build the new string
 * @return string $result A string of randomly-chosen characters
 * from $chrs
 */
function Auth_OpenID_randomString($length, $population = null)
{
    if ($population === null) {
        return Auth_OpenID_getBytes($length);
    }

    $popsize = strlen($population);

    if ($popsize > 256) {
        $msg = 'More than 256 characters supplied to ' . __FUNCTION__;
        trigger_error($msg, E_USER_ERROR);
    }

    $duplicate = 256 % $popsize;

    $str = "";
    for ($i = 0; $i < $length; $i++) {
        do {
            $n = ord(Auth_OpenID_getBytes(1));
        } while ($n < $duplicate);

        $n %= $popsize;
        $str .= $population[$n];
    }

    return $str;
}

?>