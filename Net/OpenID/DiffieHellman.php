<?php

if (extension_loaded('gmp') || @dl('gmp.' . PHP_SHLIB_SUFFIX) ||
    @dl('php_gmp.' . PHP_SHLIB_SUFFIX)) {

    define('Net_OpenID_math_type', 'gmp');

    // XXX: untested!
    class Net_OpenID_DiffieHellman {
        var $DEFAULT_MOD = '155172898181473697471232257763715539915724801966915404479707795314057629378541917580651227423698188993727816152646631438561595825688188889951272158842675419950341258706556549803580104870537681476726513255747040765857479291291572334510643245094715007229621094194349783925984760375594985848253359305585439638443';

        var $DEFAULT_GEN = '2';

        var $mod;
        var $gen;
        var $private;

        function generateRandom() {
            // XXX: not cryptographically secure (potentially predictable)
            $limb_cnt = 31;
            do {
                $rdm = gmp_random($limb_cnt--);
            } while (gmp_cmp( $minval, $rdm) > 0);
            return $rdm;
        }

        function Net_OpenID_DiffieHellman($mod=NULL, $gen=NULL, $private=NULL) {
            if ($mod === NULL) {
                $this->mod = gmp_init($this->DEFAULT_MOD, 10);
            } else {
                $this->mod = $mod;
            }

            if ($gen === NULL) {
                $this->gen = gmp_init($this->DEFAULT_GEN, 10);
            } else {
                $this->gen = $gen;
            }

            $this->private =
                $private === NULL ? $this->generateRandom() : $private;

            $this->public = user_error("not implemented", E_USER_ERROR);
        }

        function createKeyExchange( ) {
            return Net_OpenID_BigInt::powm( $this->g, $this->x, $this->p);
        }

        function decryptKeyExchange( $keyEx ) {
            return Net_OpenID_BigInt::powm( $keyEx, $this->x, $this->p );
        }
    }

} elseif (extension_loaded('bcmath') || @dl('bcmath.' . PHP_SHLIB_SUFFIX) ||
          @dl('php_bcmath.' . PHP_SHLIB_SUFFIX)) {

    define('Net_OpenID_math_type', 'bcmath');

    if (!function_exists('bcpowmod')) {
        // PHP4 does not expose bcpowmod, so we have to implement it here
        /**
         * (base ^ exponent) % modulus
         */
        function bcpowmod($base, $exponent, $modulus) {
            $square = bcmod($base, $modulus);
            $result = '1';
            while( bccomp( $exponent, 0 ) > 0 ) {
                if (bcmod($exponent, 2)) {
                    // result = (result * square) % modulus
                    $result = bcmod(bcmul($result, $square), $modulus);
                }
                $square = bcmod(bcmul($square, $square), $modulus);
                $exponent = bcdiv($exponent, 2);
            }
            return $result;
        }
    }

    class Net_OpenID_DiffieHellman {
        var $DEFAULT_MOD = '155172898181473697471232257763715539915724801966915404479707795314057629378541917580651227423698188993727816152646631438561595825688188889951272158842675419950341258706556549803580104870537681476726513255747040765857479291291572334510643245094715007229621094194349783925984760375594985848253359305585439638443';

        var $DEFAULT_GEN = '2';

        var $mod;
        var $gen;
        var $private;
        var $public;

        function Net_OpenID_DiffieHellman($mod=NULL, $gen=NULL, $private=NULL) {
            $this->mod = $mod === NULL ? $this->DEFAULT_MOD : $mod;
            $this->gen = $gen === NULL ? $this->DEFAULT_GEN : $gen;
            $this->private =
                $private === NULL ? $this->generateRandom() : $private;

            $this->public = bcpowmod($this->gen, $this->private, $this->mod);
        }

        function generateRandom() {
            // XXX: not cryptographically secure (predictable!!!)
            // XXX: also, way too small (usually)
            // FIXME
            return mt_rand(1, $this->mod);
        }

        function getSharedSecret($composite) {
            return bcpowmod($composite, $this->private, $this->mod);
        }

        function getPublicKey() {
            return $this->public;
        }

    }

} else {
    trigger_error("No usable big int library present (gmp or bcmath). " .
                  "Only dumb mode OpenID is available.",
                  E_USER_NOTICE);
}
