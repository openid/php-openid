<?php

/**
 * This module contains code for dealing with associations between
 * consumers and servers.
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
 * Includes for utility functions.
 */
require_once('CryptUtil.php');
require_once('KVForm.php');
require_once('OIDUtil.php');

/*
 * This class represents an association between a server and a
 * consumer.  In general, users of this library will never see
 * instances of this object.  The only exception is if you implement a
 * custom Net_OpenID_OpenIDStore.
 *
 * If you do implement such a store, it will need to store the values
 * of the handle, secret, issued, lifetime, and assoc_type instance
 * variables.
*/
class Net_OpenID_Association {

    // This is a HMAC-SHA1 specific value.
    var $SIG_LENGTH = 20;

    // The ordering and name of keys as stored by serialize
    var $assoc_keys = array(
                            'version',
                            'handle',
                            'secret',
                            'issued',
                            'lifetime',
                            'assoc_type'
                            );

    /**
     * This is an alternate constructor used by the OpenID consumer
     * library to create associations.  C{L{OpenIDStore
     * <openid.store.interface.OpenIDStore>}} implementations
     * shouldn't use this constructor.
     *
     * @param integer $expires_in This is the amount of time this
     * association is good for, measured in seconds since the
     * association was issued.
     *
     * @param string $handle This is the handle the server gave this
     * association.
     *
     * @param string secret This is the shared secret the server
     * generated for this association.
     *
     * @param assoc_type: This is the type of association this
     * instance represents.  The only valid value of this field
     * at this time is C{'HMAC-SHA1'}, but new types may be
     * defined in the future.
     */
    function fromExpiresIn($expires_in, $handle, $secret, $assoc_type)
    {
        $issued = time();
        $lifetime = $expires_in;
        return new Net_OpenID_Association($handle, $secret,
                                          $issued, $lifetime, $assoc_type);
    }

    /**
     * This is the standard constructor for creating an association.
     *
     * @param string $handle This is the handle the server gave this
     * association.
     *
     * @param string $secret This is the shared secret the server
     * generated for this association.
     *
     * @param integer $issued This is the time this association was
     * issued, in seconds since 00:00 GMT, January 1, 1970.  (ie, a
     * unix timestamp)
     *
     * @param integer $lifetime This is the amount of time this
     * association is good for, measured in seconds since the
     * association was issued.
     *
     * @param string $assoc_type This is the type of association this
     * instance represents.  The only valid value of this field at
     * this time is C{'HMAC-SHA1'}, but new types may be defined in
     * the future.
     */
    function Net_OpenID_Association(
        $handle, $secret, $issued, $lifetime, $assoc_type)
    {
        if ($assoc_type != 'HMAC-SHA1') {
            $fmt = 'HMAC-SHA1 is the only supported association type (got %s)';
            trigger_error(sprintf($fmt, $assoc_type), E_USER_ERROR);
        }

        $this->handle = $handle;
        $this->secret = $secret;
        $this->issued = $issued;
        $this->lifetime = $lifetime;
        $this->assoc_type = $assoc_type;
    }

    /**
     * This returns the number of seconds this association is still
     * valid for, or 0 if the association is no longer valid.
     *
     * @return integer $seconds The number of seconds this association
     * is still valid for, or 0 if the association is no longer valid.
     */
    function getExpiresIn($now = null)
    {
        if ($now == null) {
            $now = time();
        }

        return max(0, $this->issued + $this->lifetime - $now);
    }

    /**
     * This checks to see if two C{L{Association}} instances represent
     * the same association.
     *
     * @return bool $result true if the two instances represent the
     * same association, false otherwise.
     */
    function equal($other)
    {
        return ((gettype($this) == gettype($other))
                && ($this->handle == $other->handle)
                && ($this->secret == $other->secret)
                && ($this->issued == $other->issued)
                && ($this->lifetime == $other->lifetime)
                && ($this->assoc_type == $other->assoc_type));
    }

    /**
     * This checks to see if two C{L{Association}} instances
     * represent different associations.
     *
     * @return bool $result true if the two instances represent
     * different associations, false otherwise.
     */
    function not_equal($other)
    {
        return !($this->equal($other));
    }

    /**
     * Convert an association to KV form.
     *
     * @return string $result String in KV form suitable for
     * deserialization by deserialize.
     */
    function serialize()
    {
        $data = array(
                     'version' => '2',
                     'handle' => $this->handle,
                     'secret' => Net_OpenID_toBase64($this->secret),
                     'issued' => strval(intval($this->issued)),
                     'lifetime' => strval(intval($this->lifetime)),
                     'assoc_type' => $this->assoc_type
                     );

        assert(array_keys($data) == $this->assoc_keys);

        return Net_OpenID_KVForm::arrayToKV($data, $strict = true);
    }

    /**
     * Parse an association as stored by serialize().  This is the
     * inverse of serialize.
     *
     * @param string $assoc_s Association as serialized by serialize()
     * @return Net_OpenID_Association $result instance of this class
     */
    function deserialize($class_name, $assoc_s)
    {
        $pairs = Net_OpenID_KVForm::kvToArray($assoc_s, $strict = true);
        $keys = array();
        $values = array();
        foreach ($pairs as $key => $value) {
            if (is_array($value)) {
                list($key, $value) = $value;
            }
            $keys[] = $key;
            $values[] = $value;
        }

        $class_vars = get_class_vars($class_name);
        $class_assoc_keys = $class_vars['assoc_keys'];
        if ($keys != $class_assoc_keys) {
            trigger_error('Unexpected key values: ' . strval($keys),
                          E_USER_WARNING);
            return null;
        }

        list($version, $handle, $secret, $issued, $lifetime, $assoc_type) =
            $values;

        if ($version != '2') {
            trigger_error('Unknown version: ' . $version, E_USER_WARNING);
            return null;
        }

        $issued = intval($issued);
        $lifetime = intval($lifetime);
        $secret = Net_OpenID_fromBase64($secret);

        return new $class_name(
            $handle, $secret, $issued, $lifetime, $assoc_type);
    }

    /**
     * Generate a signature for a sequence of (key, value) pairs
     *
     * @param array $pairs The pairs to sign, in order.  This is an
     * array of two-tuples.
     * @return string $signature The binary signature of this sequence
     * of pairs
     */
    function sign($pairs)
    {
        assert($this->assoc_type == 'HMAC-SHA1');
        $kv = Net_OpenID_KVForm::arrayToKV($pairs);
        return Net_OpenID_hmacSha1($this->secret, $kv);
    }

    /**
     * Generate a signature for some fields in a dictionary
     *
     * @param array $fields The fields to sign, in order; this is an
     * array of strings.
     * @param array $data Dictionary of values to sign (an array of
     * string => string pairs).
     * @return string $signature The signature, base64 encoded
     */
    function signDict($fields, $data, $prefix = 'openid.')
    {
        $pairs = array();
        foreach ($fields as $field) {
            $pairs[] = array($field, $data[$prefix . $field]);
        }

        return Net_OpenID_toBase64($this->sign($pairs));
    }

    function addSignature($fields, $data, $prefix = 'openid.')
    {
        $sig = $this->signDict($fields, $data, $prefix);
        $signed = implode(",", $fields);
        $data[$prefix . 'sig'] = $sig;
        $data[$prefix . 'signed'] = $signed;
    }

    function checkSignature($data, $prefix = 'openid.')
    {
        $signed = $data[$prefix . 'signed'];
        $fields = explode(",", $signed);
        $expected_sig = $this->signDict($fields, $data, $prefix);
        $request_sig = $data[$prefix . 'sig'];

        return ($request_sig == $expected_sig);
    }
}

?>