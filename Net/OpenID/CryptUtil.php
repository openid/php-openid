<?php

/**
 * CryptUtil: A suite of wrapper utility functions for the OpenID
 * library.
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
 * Require the HMAC/SHA-1 implementation for creating such hashes.
 */
require_once('HMACSHA1.php');

if (!defined('Net_OpenID_RAND_SOURCE')) {
    /**
     * The filename for a source of random bytes. Define this yourself
     * if you have a different source of randomness.
     */
    define('Net_OpenID_RAND_SOURCE', '/dev/urandom');
}

/**
 * Net_OpenID_CryptUtil houses static utility functions.
 *
 * @package OpenID
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
     * @return string $bytes random bytes
     */
    function getBytes($num_bytes) {
        $bytes = '';
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

    function maxint() {
        /**
         * quick-and-dirty function for PHP int size -- assumes
         * largest integer is of form 2^n - 1
         */
        $to_test = pow(2, 16);
        while (1) {
            $last = $to_test;
            $to_test = 2 * $to_test;
            if (($to_test < $last) || (!is_int($to_test))) {
                return($last + ($last - 1));
            }
        }
    }

    /**
     * Computes the SHA1 hash.
     *
     * @param string $str The input string.
     * @static
     * @return string The resulting SHA1 hash.
     */
    function sha1($str) {
        return sha1($str, true);
    }

    /**
     * Computes an HMAC-SHA1 digest.
     */
    function hmacSha1($key, $text) {
        return Net_OpenID_HMACSHA1($key, $text);
    }

    function fromBase64($str) {
        return base64_decode($str);
    }

    function toBase64($str) {
        return base64_encode($str);
    }

    function longToBinary($long) {

        $lib =& Net_OpenID_MathLibrary::getLibWrapper();

        if ($lib->cmp($long, 0) < 0) {
            print "numToBytes takes only positive integers.";
            return null;
        }

        if ($long == 0) {
            return "\x00";
        }

        $bytes = array();

        while ($long) {
            array_unshift($bytes, $lib->mod($long, 256));
            $long = $lib->div($long, pow(2, 8));
        }

        if ($bytes && ($bytes[0] > 127)) {
            array_unshift($bytes, 0);
        }

        $string = '';
        foreach ($bytes as $byte) {
            $string .= pack('C', $byte);
        }

        return $string;
    }

    function binaryToLong($str) {

        $lib =& Net_OpenID_MathLibrary::getLibWrapper();

        if ($str === null) {
            return null;
        }

        // Use array_merge to return a zero-indexed array instead of a
        // one-indexed array.
        $bytes = array_merge(unpack('C*', $str));

        $n = $lib->init(0);

        if ($bytes && ($bytes[0] > 127)) {
            print "bytesToNum works only for positive integers.";
            return null;
        }

        foreach ($bytes as $byte) {
            $n = $lib->mul($n, pow(2, 8));
            $n = $lib->add($n, $byte);
        }

        return $n;
    }

    function base64ToLong($str) {
        return Net_OpenID_CryptUtil::binaryToLong(Net_OpenID_CryptUtil::fromBase64($str));
    }

    function longToBase64($long) {
        return Net_OpenID_CryptUtil::toBase64(Net_OpenID_CryptUtil::longToBinary($long));
    }

    function strxor($x, $y) {
        if (strlen($x) != strlen($y)) {
            return null;
        }

        $str = "";
        for ($i = 0; $i < strlen($x); $i++) {
            $str .= chr(ord($x[$i]) ^ ord($y[$i]));
        }

        return $str;
    }

    function reversed($list) {
        if (is_string($list)) {
            return strrev($list);
        } else if (is_array($list)) {
            return array_reverse($list);
        } else {
            return null;
        }
    }

    function randrange($start, $stop = null, $step = 1) {

        static $Net_OpenID_CryptUtil_duplicate_cache = array();
        $lib =& Net_OpenID_MathLibrary::getLibWrapper();

        if ($stop == null) {
            $stop = $start;
            $start = 0;
        }

        $r = $lib->sub($stop, $start);

        if (array_key_exists($r, $Net_OpenID_CryptUtil_duplicate_cache)) {
            list($duplicate, $nbytes) = $Net_OpenID_CryptUtil_duplicate_cache[$r];
        } else {
            $rbytes = Net_OpenID_CryptUtil::longToBinary($r);
            if ($rbytes[0] == '\x00') {
                $nbytes = strlen($rbytes) - 1;
            } else {
                $nbytes = strlen($rbytes);
            }

            $mxrand = $lib->pow(256, $nbytes);

            // If we get a number less than this, then it is in the
            // duplicated range.
            $duplicate = $lib->mod($mxrand, $r);

            if (count($Net_OpenID_CryptUtil_duplicate_cache) > 10) {
                $Net_OpenID_CryptUtil_duplicate_cache = array();
            }

            $Net_OpenID_CryptUtil_duplicate_cache[$r] = array($duplicate, $nbytes);
        }

        while (1) {
            $bytes = '\x00' . Net_OpenID_CryptUtil::getBytes($nbytes);
            $n = Net_OpenID_CryptUtil::binaryToLong($bytes);
            // Keep looping if this value is in the low duplicated range
            if ($n >= $duplicate) {
                break;
            }
        }
        return $lib->add($start, $lib->mul($lib->mod($n, $r), $step));
    }

    /**
     * Produce a string of length random bytes, chosen from chrs.
     */
    function randomString($length, $chrs = null) {
        if ($chrs == null) {
            return getBytes($length);
        } else {
            $n = strlen($chrs);
            $str = "";
            for ($i = 0; $i < $length; $i++) {
                $str .= $chrs[Net_OpenID_CryptUtil::randrange($n)];
            }
            return $str;
        }
    }
}

/**
 * Net_OpenID_MathWrapper is a base class that defines the interface
 * to whatever large number math library is available, if any.
 *
 * @package OpenID
 */
class Net_OpenID_MathWrapper {
    var $type = 'dumb';

    function random($min, $max) {
        return mt_rand($min, $max);
    }

    function pow($base, $exponent) {
        return pow($base, $exponent);
    }

    function add($x, $y) {
        return $x + $y;
    }

    function cmp($x, $y) {
        if ($x > $y) {
            return 1;
        } else if ($x < $y) {
            return -1;
        } else {
            return 0;
        }
    }

    function init($number, $base = 10) {
        return $number;
    }

    function mod($base, $modulus) {
        return $base % $modulus;
    }

    function mul($x, $y) {
        return $x * $y;
    }

    function sub($x, $y) {
        return $x - $y;
    }

    function div($x, $y) {
        return $x / $y;
    }

    function powmod($base, $exponent, $modulus) {
        $square = $this->mod($base, $modulus);
        $result = '1';
        while($this->cmp($exponent, 0) > 0) {
            if ($this->mod($exponent, 2)) {
                $result = $this->mod($this->mul($result, $square), $modulus);
            }
            $square = $this->mod($this->mul($square, $square), $modulus);
            $exponent = $this->div($exponent, 2);
        }
        return $result;
    }
}

/**
 * Net_OpenID_BcMathWrapper implements the Net_OpenID_MathWrapper
 * interface and wraps the functionality provided by the BCMath
 * library.
 *
 * @package OpenID
 */
class Net_OpenID_BcMathWrapper extends Net_OpenID_MathWrapper {
    var $type = 'bcmath';

    function random($min, $max) {
        return mt_rand($min, $max);
    }

    function add($x, $y) {
        return bcadd($x, $y);
    }

    function sub($x, $y) {
        return bcsub($x, $y);
    }

    function pow($base, $exponent) {
        return bcpow($base, $exponent);
    }

    function cmp($x, $y) {
        return bccomp($x, $y);
    }

    function init($number, $base = 10) {
        return $number;
    }

    function mod($base, $modulus) {
        return bcmod($base, $modulus);
    }

    function mul($x, $y) {
        return bcmul($x, $y);
    }

    function div($x, $y) {
        return bcdiv($x, $y);
    }
}

/**
 * Net_OpenID_GmpMathWrapper implements the Net_OpenID_MathWrapper
 * interface and wraps the functionality provided by the GMP library.
 *
 * @package OpenID
 */
class Net_OpenID_GmpMathWrapper extends Net_OpenID_MathWrapper {
    var $type = 'gmp';

    function random($min, $max) {
        return gmp_random($max);
    }

    function add($x, $y) {
        return gmp_add($x, $y);
    }

    function sub($x, $y) {
        return gmp_sub($x, $y);
    }

    function pow($base, $exponent) {
        return gmp_pow($base, $exponent);
    }

    function cmp($x, $y) {
        return gmp_cmp($x, $y);
    }

    function init($number, $base = 10) {
        return gmp_init($number, $base);
    }

    function mod($base, $modulus) {
        return gmp_mod($base, $modulus);
    }

    function mul($x, $y) {
        return gmp_mul($x, $y);
    }

    function div($x, $y) {
        return gmp_div($x, $y);
    }

    function powmod($base, $exponent, $modulus) {
        return gmp_powm($base, $exponent, $modulus);
    }
}

$Net_OpenID___mathLibrary = null;

/**
 * Net_OpenID_MathLibrary checks for the presence of a module in
 * Net_OpenID_supported_extensions and supplies an instance of a
 * wrapper for that extension module.
 *
 * @package OpenID
 */
class Net_OpenID_MathLibrary {

    function &getLibWrapper() {
        $Net_OpenID_supported_extensions = array(
                                                 array('modules' => array('gmp', 'php_gmp'),
                                                       'extension' => 'gmp',
                                                       'class' => 'Net_OpenID_GmpMathWrapper'),
                                                 array('modules' => array('bcmath', 'php_bcmath'),
                                               'extension' => 'bcmath',
                                                       'class' => 'Net_OpenID_BcMathWrapper')
                                                 );

        global $Net_OpenID___mathLibrary;

        if (!$Net_OpenID___mathLibrary) {
            $loaded = false;

            foreach ($Net_OpenID_supported_extensions as $extension) {
                if ($extension['extension'] &&
                    extension_loaded($extension['extension'])) {
                    $loaded = true;
                }

                if (!$loaded) {
                    foreach ($extension['modules'] as $module) {
                        if (@dl($module . "." . PHP_SHLIB_SUFFIX)) {
                            $loaded = true;
                            break;
                        }
                    }
                }

                if ($loaded) {
                    $classname = $extension['class'];
                    $Net_OpenID___mathLibrary =& new $classname();
                    break;
                }
            }

            if (!$Net_OpenID___mathLibrary) {
                $Net_OpenID___mathLibrary =& new Net_OpenID_MathWrapper();
            }
        }

        return $Net_OpenID___mathLibrary;
    }
}

?>