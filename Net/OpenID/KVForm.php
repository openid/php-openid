<?php

class Net_OpenID_KVForm {
    function arrayToKV($values) {
        $serialized = '';
        foreach ($values as $key => $value) {
            if (strpos($key, ':') !== FALSE) {
                trigger_error('":" in key:' . addslashes($key),
                              E_USER_WARNING);
                return NULL;
            }

            if (strpos($key, "\n") !== FALSE) {
                trigger_error('"\n" in key:' . addslashes($key),
                              E_USER_WARNING);
                return NULL;
            }

            if (strpos($value, "\n") !== FALSE) {
                trigger_error('"\n" in value:' . addslashes($key),
                              E_USER_WARNING);
                return NULL;
            }
            $serialized .= "$key:$value\n";
        }
        return $serialized;
    }

    function kvToArray($kvs) {
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
}

?>