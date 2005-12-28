<?php

if (!defined('Net_OpenID_RAND_SOURCE')) {
    /**
     * The filename for a source of random bytes. Define this yourself
     * if you have a different source of randomness.
     */
    define('Net_OpenID_RAND_SOURCE', '/dev/urandom');
}

/**
 * Cryptographic utility functions
 */
class Net_OpenID_CryptUtil {
    /** 
     * Get the specified number of random bytes.
     *
     * Attempts to use a cryptographically secure (not predictable)
     * source of randomness if available. If there is no high-entropy
     * randomness source available, it will fail. As a last resort,
     * for non-critical systems, define
     * <code>Net_OpenID_USE_INSECURE_RAND</code>, and the code will
     * fall back on a pseudo-random number generator.
     *
     * @static
     * @param int $num_bytes The length of the return value
     * @return string $num_bytes random bytes
     */
    function getBytes($num_bytes) {
        $f = @fopen("/dev/urandom", "r");
        if ($f === FALSE) {
            if (!defined(Net_OpenID_USE_INSECURE_RAND)) {
                trigger_error('Set Net_OpenID_USE_INSECURE_RAND to ' .
                              'continue with insecure random.',
                              E_USER_ERROR);
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
}

?>