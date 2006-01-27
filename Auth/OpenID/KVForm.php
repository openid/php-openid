<?php

/**
 * This is the KVForm module.
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
 * @access private
 */
function Auth_OpenID_arrayToKV($values)
{
    if ($values === null) {
        return null;
    }

    $serialized = '';
    foreach ($values as $key => $value) {
        if (is_array($value)) {
            list($key, $value) = $value;
        }

        if (strpos($key, ':') !== false) {
            trigger_error('":" in key:' . addslashes($key), E_USER_WARNING);
            return null;
        }

        if (strpos($key, "\n") !== false) {
            trigger_error('"\n" in key:' . addslashes($key), E_USER_WARNING);
            return null;
        }

        if (strpos($value, "\n") !== false) {
            trigger_error('"\n" in value:' . addslashes($value),
                          E_USER_WARNING);
            return null;
        }
        $serialized .= "$key:$value\n";
    }
    return $serialized;
}

function Auth_OpenID_kvToArray($kvs)
{
    $lines = explode("\n", $kvs);

    $last = array_pop($lines);
    if ($last !== '') {
        trigger_error('No newline at end of kv string:' . addslashes($kvs),
                      E_USER_WARNING);
        array_push($lines, $last);
    }

    $values = array();

    for ($lineno = 0; $lineno < count($lines); $lineno++) {
        $line = $lines[$lineno];
        $kv = explode(':', $line, 2);
        if (count($kv) != 2) {
            $esc = addslashes($line);
            trigger_error("No colon on line $lineno: $esc",
                          E_USER_WARNING);
            continue;
        }

        $key = $kv[0];
        $tkey = trim($key);
        if ($tkey != $key) {
            $esc = addslashes($key);
            trigger_error("Whitespace in key on line $lineno: '$esc'",
                          E_USER_WARNING);
        }

        $value = $kv[1];
        $tval = trim($value);
        if ($tval != $value) {
            $esc = addslashes($value);
            trigger_error("Whitespace in value on line $lineno: '$esc'",
                          E_USER_WARNING);
        }

        $values[$tkey] = $tval;
    }

    return $values;
}

?>