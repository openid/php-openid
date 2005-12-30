<?php

/**
 * The OpenID library's Diffie-Hellman implementation.
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
 * Require CryptUtil because we need to get a Net_OpenID_MathWrapper
 * object.
 */
require_once('CryptUtil.php');

/**
 * The Diffie-Hellman key exchange class.  This class relies on
 * Net_OpenID_MathLibrary to perform large number operations.
 *
 * @package OpenID
 */
class Net_OpenID_DiffieHellman {
    var $DEFAULT_MOD = '155172898181473697471232257763715539915724801966915404479707795314057629378541917580651227423698188993727816152646631438561595825688188889951272158842675419950341258706556549803580104870537681476726513255747040765857479291291572334510643245094715007229621094194349783925984760375594985848253359305585439638443';

    var $DEFAULT_GEN = '2';

    var $mod;
    var $gen;
    var $private;
    var $lib = null;

    function Net_OpenID_DiffieHellman($mod = NULL, $gen = NULL, $private = NULL) {

        $this->lib =& Net_OpenID_MathLibrary::getLibWrapper();

        if (!$this->lib) {
            // This should NEVER occur because even if no math
            // extensions can be found, we should get an instance of
            // Net_OpenID_MathWrapper, but if there's a bug in
            // Net_OpenID_MathLibrary::getLibWrapper, it might.
            trigger_error("Big integer fallback implementation unavailable.", E_USER_ERROR);
        }

        if ($this->lib->type == 'dumb') {
            trigger_error("No usable big integer library present (gmp or bcmath). " .
                          "Use of this math library wrapper is not permitted without big " .
                          "integer support.",
                          E_USER_ERROR);
        }

        if ($mod === NULL) {
            $this->mod = $this->lib->init($this->DEFAULT_MOD);
        } else {
            $this->mod = $mod;
        }

        if ($gen === NULL) {
            $this->gen = $this->lib->init($this->DEFAULT_GEN);
        } else {
            $this->gen = $gen;
        }

        $this->private =
            ($private === NULL) ? $this->generateRandom() : $private;

        $this->public = $this->lib->powmod($this->gen, $this->private, $this->mod);
    }

    function generateRandom() {
        return $this->lib->random(1, $this->mod);
    }

    function createKeyExchange() {
        return $this->lib->powmod($this->g, $this->x, $this->p);
    }

    function decryptKeyExchange($keyEx) {
        return $this->lib->powmod($keyEx, $this->x, $this->p);
    }

    function getSharedSecret($composite) {
        return $this->lib->powmod($composite, $this->private, $this->mod);
    }

    function getPublicKey() {
        return $this->public;
    }
}
