<?php

/**
 * OpenID protocol key-value/comma-newline format parsing and
 * serialization
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

/**
 * Container for key-value/comma-newline OpenID format and parsing
 */
class Auth_OpenID_KVForm {
    /**
     * Issue a warning when parsing KV form
     *
     * @static
     * @access private
     */
    function _warn($msg)
    {
        trigger_error($msg, E_USER_WARNING);
    }

    /**
     * Convert an OpenID colon/newline separated string into an
     * associative array
     *
     * @static
     * @access private
     */
    function toArray($kvs, $strict=false)
    {
        $lines = explode("\n", $kvs);

        $last = array_pop($lines);
        if ($last !== '') {
            $msg = 'No newline at end of kv string:' . var_export($kvs, true);
            Auth_OpenID_KVForm::_warn($msg);
            array_push($lines, $last);
            if ($strict) {
                return false;
            }
        }

        $values = array();

        for ($lineno = 0; $lineno < count($lines); $lineno++) {
            $line = $lines[$lineno];
            $kv = explode(':', $line, 2);
            if (count($kv) != 2) {
                $msg = "No colon on line $lineno: " . var_export($line, true);
                Auth_OpenID_KVForm::_warn($msg);
                if ($strict) {
                    return false;
                }
                continue;
            }

            $key = $kv[0];
            $tkey = trim($key);
            if ($tkey != $key) {
                $msg = "Whitespace in key on line $lineno:" .
                    var_export($key, true);
                Auth_OpenID_KVForm::_warn($msg);
                if ($strict) {
                    return false;
                }
            }

            $value = $kv[1];
            $tval = trim($value);
            if ($tval != $value) {
                $msg = "Whitespace in value on line $lineno: " .
                    var_export($value, true);
                Auth_OpenID_KVForm::_warn($msg);
                if ($strict) {
                    return false;
                }
            }

            $values[$tkey] = $tval;
        }

        return $values;
    }

    /**
     * Convert an array into an OpenID colon/newline separated string
     *
     * @static
     * @access private
     */
    function fromArray($values)
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
                $msg = '":" in key:' . var_export($key, true);
                Auth_OpenID_KVForm::_warn($msg);
                return null;
            }

            if (strpos($key, "\n") !== false) {
                $msg = '"\n" in key:' . var_export($key, true);
                Auth_OpenID_KVForm::_warn($msg);
                return null;
            }

            if (strpos($value, "\n") !== false) {
                $msg = '"\n" in value:' . var_export($value, true);
                Auth_OpenID_KVForm::_warn($msg);
                return null;
            }
            $serialized .= "$key:$value\n";
        }
        return $serialized;
    }
}

?>