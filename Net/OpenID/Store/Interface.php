<?php

class Net_OpenID_OpenIDStore {
    /**
     * This is the interface for the store objects the OpenID library
     * uses. It is a single class that provides all of the persistence
     * mechanisms that the OpenID library needs, for both servers and
     * consumers.
     *
     * @cvar $AUTH_KEY_LEN: The length of the auth key that should be
     * returned by the C{L{getAuthKey}} method.
     *
     * @sort: storeAssociation, getAssociation, removeAssociation,
     * storeNonce, useNonce, getAuthKey, isDumb
     */

    $AUTH_KEY_LEN = 20;

    function storeAssociation($server_url, $association) {
        /**
         * This method puts a C{L{Association
         * <openid.association.Association>}} object into storage,
         * retrievable by server URL and handle.
         *
         * @param server_url: The URL of the identity server that this
         * association is with. Because of the way the server portion
         * of the library uses this interface, don't assume there are
         * any limitations on the character set of the input
         * string. In particular, expect to see unescaped non-url-safe
         * characters in the server_url field.
         *
         * @type server_url: C{str}
         *
         * @param association: The C{L{Association
         * <openid.association.Association>}} to store.
         *
         * @type association: C{L{Association
         * <openid.association.Association>}}
         *
         * @return: C{None}
         *
         * @rtype: C{NoneType}
         */

        trigger_error("OpenIDStore::storeAssociation not implemented", E_ERROR);
    }

    function getAssociation($server_url, $handle = null) {
        /**
         * This method returns an C{L{Association
         * <openid.association.Association>}} object from storage that
         * matches the server URL and, if specified, handle. It
         * returns C{None} if no such association is found or if the
         * matching association is expired.
         *
         * If no handle is specified, the store may return any
         * association which matches the server URL. If multiple
         * associations are valid, the recommended return value for
         * this method is the one that will remain valid for the
         * longest duration.
         *
         * This method is allowed (and encouraged) to garbage collect
         * expired associations when found. This method must not
         * return expired associations.
         *
         * @param server_url: The URL of the identity server to get
         * the association for. Because of the way the server portion
         * of the library uses this interface, don't assume there are
         * any limitations on the character set of the input string.
         * In particular, expect to see unescaped non-url-safe
         * characters in the server_url field.
         *
         * @type server_url: C{str}
         *
         * @param handle: This optional parameter is the handle of the
         * specific association to get. If no specific handle is
         * provided, any valid association matching the server URL is
         * returned.
         *
         * @type handle: C{str} or C{NoneType}
         *
         * @return: The C{L{Association
         * <openid.association.Association>}} for the given identity
         * server.
         *
         * @rtype: C{L{Association <openid.association.Association>}}
         * or C{NoneType}
         */

        trigger_error("OpenIDStore::getAssociation not implemented", E_ERROR);
    }

    function removeAssociation($server_url, $handle) {
        /**
         * This method removes the matching association if it's found,
         * and returns whether the association was removed or not.
         *
         * @param server_url: The URL of the identity server the
         * association to remove belongs to. Because of the way the
         * server portion of the library uses this interface, don't
         * assume there are any limitations on the character set of
         * the input string. In particular, expect to see unescaped
         * non-url-safe characters in the server_url field.
         *
         * @type server_url: C{str}
         *
         * @param handle: This is the handle of the association to
         * remove. If there isn't an association found that matches
         * both the given URL and handle, then there was no matching
         * handle found.
         *
         * @type handle: C{str}
         *
         * @return: Returns whether or not the given association
         * existed.
         *
         * @rtype: C{bool} or C{int}
         */

        trigger_error("OpenIDStore::removeAssociation not implemented", E_ERROR);
    }

    function storeNonce($nonce) {
        /**
         * Stores a nonce. This is used by the consumer to prevent
         * replay attacks.
         *
         * @param nonce: The nonce to store.
         *
         * @type nonce: C{str}
         *
         * @return: C{None}
         *
         * @rtype: C{NoneType}
         */

        trigger_error("OpenIDStore::storeNonce not implemented", E_ERROR);
    }

    function useNonce($nonce) {
        /**
         * This method is called when the library is attempting to use
         * a nonce. If the nonce is in the store, this method removes
         * it and returns a value which evaluates as true. Otherwise
         * it returns a value which evaluates as false.
         *
         * This method is allowed and encouraged to treat nonces older
         * than some period (a very conservative window would be 6
         * hours, for example) as no longer existing, and return False
         * and remove them.
         *
         * @param nonce: The nonce to use.
         *
         * @type nonce: C{str}
         *
         * @return: Whether or not the nonce was valid.
         *
         * @rtype: C{bool} or C{int}
         */

        trigger_error("OpenIDStore::useNonce not implemented", E_ERROR);
    }

    function getAuthKey() {
        /**
         * This method returns a key used to sign the tokens, to
         * ensure that they haven't been tampered with in transit. It
         * should return the same key every time it is called. The key
         * returned should be C{L{AUTH_KEY_LEN}} bytes long.
         *
         * @return: The key. It should be C{L{AUTH_KEY_LEN}} bytes in
         * length, and use the full range of byte values. That is, it
         * should be treated as a lump of binary data stored in a
         * C{str} instance.
         *
         * @rtype: C{str}
         */

        trigger_error("OpenIDStore::getAuthKey not implemented", E_ERROR);
    }

    function isDumb() {
        /**
         * This method must return C{True} if the store is a
         * dumb-mode-style store. Unlike all other methods in this
         * class, this one provides a default implementation, which
         * returns C{False}.
         *
         * In general, any custom subclass of C{L{OpenIDStore}} won't
         * override this method, as custom subclasses are only likely
         * to be created when the store is fully functional.
         *
         * @return: C{True} if the store works fully, C{False} if the
         * consumer will have to use dumb mode to use this store.
         *
         * @rtype: C{bool}
         */

        return false;
    }
}
?>