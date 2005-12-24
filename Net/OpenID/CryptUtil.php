<?php

class Net_OpenID_CryptUtil {
    function _getFourBytes() {
        $x = mt_rand();
        
        $sources = array(
            time(),
            getmypid(),
            getmygid(),
            getmyuid(),
            disk_free_space(__FILE__)
            );

        foreach ($sources as $ent) {
            $x ^= $ent;
            mt_srand($x);
            $x = mt_rand();
        }
        return $x;
    }

    function getBytes($num_bytes) {
        $f = @fopen("/dev/urandom", "r");
        if ($f === FALSE) {
            $bytes = '';
            for ($i = 0; $i < $num_bytes; $i += 4) {
                $bytes .= Net_OpenID_CryptUtil::_getFourBytes();
            }
            $bytes = substr($bytes, 0, $num_bytes);
        } else {
            $bytes = fread($f, $num_bytes);
            fclose($f);
        }
        return $bytes;
    }
}

?>