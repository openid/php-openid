<?php

/**
 * Miscellaneous utility values and functions for OpenID and Yadis.
 *
 * @package OpenID
 * @author JanRain, Inc. <openid@janrain.com>
 * @copyright 2005-2008 Janrain, Inc.
 * @license http://www.apache.org/licenses/LICENSE-2.0 Apache
 */

function Auth_Yadis_getUCSChars()
{
    return [
        [0xA0, 0xD7FF],
        [0xF900, 0xFDCF],
        [0xFDF0, 0xFFEF],
        [0x10000, 0x1FFFD],
        [0x20000, 0x2FFFD],
        [0x30000, 0x3FFFD],
        [0x40000, 0x4FFFD],
        [0x50000, 0x5FFFD],
        [0x60000, 0x6FFFD],
        [0x70000, 0x7FFFD],
        [0x80000, 0x8FFFD],
        [0x90000, 0x9FFFD],
        [0xA0000, 0xAFFFD],
        [0xB0000, 0xBFFFD],
        [0xC0000, 0xCFFFD],
        [0xD0000, 0xDFFFD],
        [0xE1000, 0xEFFFD],
    ];
}

function Auth_Yadis_getIPrivateChars()
{
    return [
        [0xE000, 0xF8FF],
        [0xF0000, 0xFFFFD],
        [0x100000, 0x10FFFD],
    ];
}

function Auth_Yadis_pct_escape_unicode($char_match)
{
    $c = $char_match[0];
    $result = "";
    for ($i = 0; $i < strlen($c); $i++) {
        $result .= "%" . sprintf("%X", ord($c[$i]));
    }
    return $result;
}

function Auth_Yadis_startswith($s, $stuff)
{
    return strpos($s, $stuff) === 0;
}

