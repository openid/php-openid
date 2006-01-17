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

if (!defined('Auth_OpenID_RAND_SOURCE')) {
    /**
     * The filename for a source of random bytes. Define this yourself
     * if you have a different source of randomness.
     */
    define('Auth_OpenID_RAND_SOURCE', '/dev/urandom');
}

/**
 * Given a long integer, returns the number converted to a binary
 * string.  This function accepts long integer values of arbitrary
 * magnitude and uses the local large-number math library when
 * available.
 *
 * @param integer $long The long number (can be a normal PHP
 * integer or a number created by one of the available long number
 * libraries)
 * @return string $binary The binary version of $long
 */
function Auth_OpenID_longToBinary($long)
{

    $lib =& Auth_OpenID_MathLibrary::getLibWrapper();

    $cmp = $lib->cmp($long, 0);
    if ($cmp < 0) {
        $msg = __FUNCTION__ . " takes only positive integers.";
        trigger_error($msg, E_USER_ERROR);
        return null;
    }

    if ($cmp == 0) {
        return "\x00";
    }

    $bytes = array();

    while ($lib->cmp($long, 0) > 0) {
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

/**
 * Given a long integer, returns the number converted to a binary
 * string.  This function accepts "long" numbers within the PHP
 * integer range (usually 32 bits).
 *
 * @param integer $long The long number (can be a normal PHP
 * integer or a number created by one of the available long number
 * libraries)
 * @return string $binary The binary version of $long
 */
function Auth_OpenID_longToBinary_platform($long)
{

    if ($long < 0) {
        $msg = __FUNCTION__ . " takes only positive integers.";
        trigger_error($msg, E_USER_ERROR);
        return null;
    }

    return pack('N', $long);
}

/**
 * Converts a long number to its base64-encoded representation.
 *
 * @param integer $long The long number to be converted
 * @return string $str The base64-encoded version of $long
 */
function Auth_OpenID_longToBase64($long)
{
    return base64_encode(Auth_OpenID_longToBinary($long));
}

/**
 * Auth_OpenID_CryptUtil houses static utility functions.
 *
 * @package OpenID
 * @static
 */
class Auth_OpenID_CryptUtil {
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
    function getBytes($num_bytes)
    {
        $bytes = '';
        $f = @fopen(Auth_OpenID_RAND_SOURCE, "r");
        if ($f === false) {
            if (!defined('Auth_OpenID_USE_INSECURE_RAND')) {
                trigger_error('Set Auth_OpenID_USE_INSECURE_RAND to ' .
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

    /**
     * Computes the maximum integer value for this PHP installation.
     *
     * @return int $max_int_value The maximum integer value for this
     * PHP installation
     */
    function maxint()
    {
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
     * @return string The resulting SHA1 hash, in binary form.
     */
    function sha1($str)
    {
        return Auth_OpenID_sha1_raw($str);
    }

    /**
     * Computes an HMAC-SHA1 digest.
     *
     * @param string $key The key used to generate the HMAC-SHA1 digest
     * @param string $text The text to be hashed
     * @return string $digest The raw HMAC-SHA1 digest
     */
    function hmacSha1($key, $text)
    {
        return Auth_OpenID_HMACSHA1($key, $text);
    }

    /**
     * Converts a base64-encoded string to its raw binary equivalent.
     *
     * @param string $str The base64-encoded string to decode
     * @return string $raw The decoded binary data
     */
    function fromBase64($str)
    {
        return base64_decode($str);
    }

    /**
     * Converts a raw binary string to its base64-encoded equivalent.
     *
     * @param string $str The raw binary data to encode
     * @return string $raw The base64-encoded version of $str
     */
    function toBase64($str)
    {
        return base64_encode($str);
    }

    /**
     * Given a binary string, returns the binary string converted to a
     * long number.
     *
     * @param string $binary The binary version of a long number,
     * probably as a result of calling longToBinary
     * @return integer $long The long number equivalent of the binary
     * string $str
     */
    function binaryToLong($str)
    {
        $lib =& Auth_OpenID_MathLibrary::getLibWrapper();

        if ($str === null) {
            return null;
        }

        // Use array_merge to return a zero-indexed array instead of a
        // one-indexed array.
        $bytes = array_merge(unpack('C*', $str));

        $n = $lib->init(0);

        if ($bytes && ($bytes[0] > 127)) {
            trigger_error("bytesToNum works only for positive integers.",
                          E_USER_WARNING);
            return null;
        }

        foreach ($bytes as $byte) {
            $n = $lib->mul($n, pow(2, 8));
            $n = $lib->add($n, $byte);
        }

        return $n;
    }

    /**
     * Given a binary string, returns the binary string converted to a
     * long number.
     *
     * @param string $binary The binary version of a long number,
     * probably as a result of calling longToBinary
     * @return integer $long The long number equivalent of the binary
     * string $str
     */
    function binaryToLong_platform($str)
    {
        if ($str === null) {
            return null;
        }

        $data = unpack('Nx', $str);
        return $data['x'];
    }

    /**
     * Converts a base64-encoded string to a long number.
     *
     * @param string $str A base64-encoded string
     * @return integer $long A long number
     */
    function base64ToLong($str)
    {
        return Auth_OpenID_CryptUtil::binaryToLong(
                      Auth_OpenID_CryptUtil::fromBase64($str));
    }

    /**
     * Given two strings of equal length, computes the exclusive-OR of
     * the two strings' ordinal values and returns the resulting
     * string.
     *
     * @param string $x A string
     * @param string $y A string
     * @return string $result The result of $x XOR $y
     */
    function strxor($x, $y)
    {
        if (strlen($x) != strlen($y)) {
            return null;
        }

        $str = "";
        for ($i = 0; $i < strlen($x); $i++) {
            $str .= chr(ord($x[$i]) ^ ord($y[$i]));
        }

        return $str;
    }

    /**
     * Reverses a string or array.
     *
     * @param mixed $list A string or an array
     * @return mixed $result The reversed string or array
     */
    function reversed($list)
    {
        if (is_string($list)) {
            return strrev($list);
        } else if (is_array($list)) {
            return array_reverse($list);
        } else {
            return null;
        }
    }

    /**
     * Returns a random number in the specified range.  This function
     * accepts $start, $stop, and $step values of arbitrary magnitude
     * and will utilize the local large-number math library when
     * available.
     *
     * @param integer $start The start of the range, or the minimum
     * random number to return
     * @param integer $stop The end of the range, or the maximum
     * random number to return
     * @param integer $step The step size, such that $result - ($step

     * * N) = $start for some N
     * @return integer $result The resulting randomly-generated number
     */
    function randrange($start, $stop = null, $step = 1)
    {

        static $Auth_OpenID_CryptUtil_duplicate_cache = array();
        $lib =& Auth_OpenID_MathLibrary::getLibWrapper();

        if ($stop == null) {
            $stop = $start;
            $start = 0;
        }

        $r = $lib->div($lib->sub($stop, $start), $step);

        // DO NOT MODIFY THIS VALUE.
        $rbytes = Auth_OpenID_longToBinary($r);

        if (array_key_exists($rbytes, $Auth_OpenID_CryptUtil_duplicate_cache)) {
            list($duplicate, $nbytes) =
                $Auth_OpenID_CryptUtil_duplicate_cache[$rbytes];
        } else {
            if ($rbytes[0] == "\x00") {
                $nbytes = strlen($rbytes) - 1;
            } else {
                $nbytes = strlen($rbytes);
            }

            $mxrand = $lib->pow(256, $nbytes);

            // If we get a number less than this, then it is in the
            // duplicated range.
            $duplicate = $lib->mod($mxrand, $r);

            if (count($Auth_OpenID_CryptUtil_duplicate_cache) > 10) {
                $Auth_OpenID_CryptUtil_duplicate_cache = array();
            }

            $Auth_OpenID_CryptUtil_duplicate_cache[$rbytes] =
                array($duplicate, $nbytes);
        }

        while (1) {
            $bytes = "\x00" . Auth_OpenID_CryptUtil::getBytes($nbytes);
            $n = Auth_OpenID_CryptUtil::binaryToLong($bytes);
            // Keep looping if this value is in the low duplicated
            // range
            if ($lib->cmp($n, $duplicate) >= 0) {
                break;
            }
        }

        return $lib->add($start, $lib->mul($lib->mod($n, $r), $step));
    }

    /**
     * Returns a random number in the specified range.  This function
     * accepts $start, $stop, and $step values within the platform
     * integer range.
     *
     * @param integer $start The start of the range, or the minimum
     * random number to return
     * @param integer $stop The end of the range, or the maximum
     * random number to return
     * @param integer $step The step size, such that $result - ($step
     * * N) = $start for some N
     * @return integer $result The resulting randomly-generated number
     */
    function randrange_platform($start, $stop = null, $step = 1)
    {

        static $Auth_OpenID_CryptUtil_duplicate_cache = array();

        if ($stop == null) {
            $stop = $start;
            $start = 0;
        }

        $r = ($stop - $start) / $step;

        // DO NOT MODIFY THIS VALUE.
        $rbytes = Auth_OpenID_longToBinary_platform($r);

        if (array_key_exists($rbytes, $Auth_OpenID_CryptUtil_duplicate_cache)) {
            list($duplicate, $nbytes) =
                $Auth_OpenID_CryptUtil_duplicate_cache[$rbytes];
        } else {
            if ($rbytes[0] == "\x00") {
                $nbytes = strlen($rbytes) - 1;
            } else {
                $nbytes = strlen($rbytes);
            }

            $mxrand = pow(256, $nbytes);

            // If we get a number less than this, then it is in the
            // duplicated range.
            $duplicate = $mxrand % $r;

            if (count($Auth_OpenID_CryptUtil_duplicate_cache) > 10) {
                $Auth_OpenID_CryptUtil_duplicate_cache = array();
            }

            $Auth_OpenID_CryptUtil_duplicate_cache[$rbytes] =
                array($duplicate, $nbytes);
        }

        while (1) {
            $bytes = "\x00" . Auth_OpenID_CryptUtil::getBytes($nbytes);
            $n = Auth_OpenID_CryptUtil::binaryToLong_platform($bytes);
            // Keep looping if this value is in the low duplicated
            // range
            if ($n >= $duplicate) {
                break;
            }
        }

        return $start + ($n % $r) * $step;
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
    function randomString($length, $chrs = null)
    {
        if ($chrs === null) {
            return Auth_OpenID_CryptUtil::getBytes($length);
        } else {
            $n = strlen($chrs);
            $str = "";
            for ($i = 0; $i < $length; $i++) {
                $offset = Auth_OpenID_CryptUtil::randrange_platform($n);
                $str .= $chrs[$offset];
            }
            return $str;
        }
    }
}

/**
 * Exposes math library functionality.
 *
 * Auth_OpenID_MathWrapper is a base class that defines the interface
 * to a math library like GMP or BCmath.  This library will attempt to
 * use an available long number implementation.  If a library like GMP
 * is found, the appropriate Auth_OpenID_MathWrapper subclass will be
 * instantiated and used for mathematics operations on large numbers.
 * This base class wraps only native PHP functionality.  See
 * Auth_OpenID_MathWrapper subclasses for access to particular long
 * number implementations.
 *
 * @package OpenID
 */
class Auth_OpenID_MathWrapper {
    /**
     * The type of the Auth_OpenID_MathWrapper class.  This value
     * describes the library or module being wrapped.  Users of
     * Auth_OpenID_MathWrapper instances should check this value if
     * they care about the type of math functionality being exposed.
     */
    var $type = null;

    /**
     * Returns ($base to the $exponent power) mod $modulus.  In some
     * long number implementations, this may be optimized.  This
     * implementation works efficiently if we only have pow and mod.
     */
    function _powmod($base, $exponent, $modulus)
    {
        $square = $this->mod($base, $modulus);
        $result = 1;
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
 * Exposes BCmath math library functionality.
 *
 * Auth_OpenID_BcMathWrapper implements the Auth_OpenID_MathWrapper
 * interface and wraps the functionality provided by the BCMath
 * library.
 *
 * @package OpenID
 */
class Auth_OpenID_BcMathWrapper extends Auth_OpenID_MathWrapper {
    var $type = 'bcmath';

    function random($min, $max)
    {
        return mt_rand($min, $max);
    }

    function add($x, $y)
    {
        return bcadd($x, $y);
    }

    function sub($x, $y)
    {
        return bcsub($x, $y);
    }

    function pow($base, $exponent)
    {
        return bcpow($base, $exponent);
    }

    function cmp($x, $y)
    {
        return bccomp($x, $y);
    }

    function init($number, $base = 10)
    {
        return $number;
    }

    function mod($base, $modulus)
    {
        return bcmod($base, $modulus);
    }

    function mul($x, $y)
    {
        return bcmul($x, $y);
    }

    function div($x, $y)
    {
        return bcdiv($x, $y);
    }

    function powmod($base, $exponent, $modulus)
    {
        if (false && function_exists('bcpowmod')) {
            return bcpowmod($base, $exponent, $modulus);
        } else {
            return parent::powmod($base, $exponent, $modulus);
        }
    }
        
}

/**
 * Exposes GMP math library functionality.
 *
 * Auth_OpenID_GmpMathWrapper implements the Auth_OpenID_MathWrapper
 * interface and wraps the functionality provided by the GMP library.
 *
 * @package OpenID
 */
class Auth_OpenID_GmpMathWrapper extends Auth_OpenID_MathWrapper {
    var $type = 'gmp';

    function random($min, $max)
    {
        return gmp_random($max);
    }

    function add($x, $y)
    {
        return gmp_add($x, $y);
    }

    function sub($x, $y)
    {
        return gmp_sub($x, $y);
    }

    function pow($base, $exponent)
    {
        return gmp_pow($base, $exponent);
    }

    function cmp($x, $y)
    {
        return gmp_cmp($x, $y);
    }

    function init($number, $base = 10)
    {
        return gmp_init($number, $base);
    }

    function mod($base, $modulus)
    {
        return gmp_mod($base, $modulus);
    }

    function mul($x, $y)
    {
        return gmp_mul($x, $y);
    }

    function div($x, $y)
    {
        return gmp_div_q($x, $y);
    }

    function powmod($base, $exponent, $modulus)
    {
        return gmp_powm($base, $exponent, $modulus);
    }
}

$_Auth_OpenID___mathLibrary = null;

/**
 * Define the supported extensions.  An extension array has keys
 * 'modules', 'extension', and 'class'.  'modules' is an array of PHP
 * module names which the loading code will attempt to load.  These
 * values will be suffixed with a library file extension (e.g. ".so").
 * 'extension' is the name of a PHP extension which will be tested
 * before 'modules' are loaded.  'class' is the string name of a
 * Auth_OpenID_MathWrapper subclass which should be instantiated if a
 * given extension is present.
 *
 * You can define new math library implementations and add them to
 * this array.
 */
$_Auth_OpenID_supported_extensions = array(
    array('modules' => array('gmp', 'php_gmp'),
          'extension' => 'gmp',
          'class' => 'Auth_OpenID_GmpMathWrapper'),
    array('modules' => array('bcmath', 'php_bcmath'),
          'extension' => 'bcmath',
          'class' => 'Auth_OpenID_BcMathWrapper')
    );

 /**
 * Auth_OpenID_MathLibrary checks for the presence of long number
 * extension modules and returns an instance of Auth_OpenID_MathWrapper
 * which exposes the module's functionality.
 *
 * @static
 * @package OpenID
 */
class Auth_OpenID_MathLibrary {

    /**
     * A method to access an available long number implementation.
     *
     * Checks for the existence of an extension module described by
     * the local Auth_OpenID_supported_extensions array and returns an
     * instance of a wrapper for that extension module.  If no
     * extension module is found, an instance of
     * Auth_OpenID_MathWrapper is returned, which wraps the native PHP
     * integer implementation.  The proper calling convention for this
     * method is $lib =& Auth_OpenID_MathLibrary::getLibWrapper().
     *
     * This function checks for the existence of specific long number
     * implementations in the following order: GMP followed by BCmath.
     *
     * @return Auth_OpenID_MathWrapper $instance An instance of
     * Auth_OpenID_MathWrapper or one of its subclasses
     */
    function &getLibWrapper()
    {
        // The instance of Auth_OpenID_MathWrapper that we choose to
        // supply will be stored here, so that subseqent calls to this
        // method will return a reference to the same object.
        global $_Auth_OpenID___mathLibrary;
            
        if (defined('Auth_OpenID_NO_MATH_SUPPORT')) {
            $_Auth_OpenID___mathLibrary = null;
            return $_Auth_OpenID___mathLibrary;
        }

        global $_Auth_OpenID_supported_extensions;

        // If this method has not been called before, look at
        // $Auth_OpenID_supported_extensions and try to find an
        // extension that works.
        if (!$_Auth_OpenID___mathLibrary) {
            $loaded = false;
            $tried = array();

            foreach ($_Auth_OpenID_supported_extensions as $extension) {
                $tried[] = $extension['extension'];

                // See if the extension specified is already loaded.
                if ($extension['extension'] &&
                    extension_loaded($extension['extension'])) {
                    $loaded = true;
                }

                // Try to load dynamic modules.
                if (!$loaded) {
                    foreach ($extension['modules'] as $module) {
                        if (@dl($module . "." . PHP_SHLIB_SUFFIX)) {
                            $loaded = true;
                            break;
                        }
                    }
                }

                // If the load succeeded, supply an instance of
                // Auth_OpenID_MathWrapper which wraps the specified
                // module's functionality.
                if ($loaded) {
                    $classname = $extension['class'];
                    $_Auth_OpenID___mathLibrary = new $classname();
                    break;
                }
            }

            // If no extensions were found, fall back to
            // Auth_OpenID_MathWrapper so at least some platform-size
            // math can be performed.
            if (!$_Auth_OpenID___mathLibrary) {
                $triedstr = implode(", ", $tried);
                $msg = 'This PHP installation has no big integer math ' .
                    'library. Define Auth_OpenID_NO_MATH_SUPPORT to use ' .
                    'this library in dumb mode. Tried: ' . $triedstr;
                trigger_error($msg, E_USER_ERROR);
            }
        }

        return $_Auth_OpenID___mathLibrary;
    }
}

?>