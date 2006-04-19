<?php

/**
 * In-memory OpenID store implementation for testing only
 */
require_once "Auth/OpenID/Interface.php";

class Tests_Auth_OpenID_MemStore extends Auth_OpenID_OpenIDStore {
    var $assocs = null;
    var $nonces = null;

    function Tests_Auth_OpenID_MemStore($auth_key=null)
    {
        $this->assocs = array();
        $this->nonces = array();
        $this->auth_key = $auth_key;
    }

    function getKey($server_url, $handle)
    {
        return serialize(array($server_url, $handle));
    }

    function getAssocPairs()
    {
        $pairs = array();
        foreach ($this->assocs as $key => $assoc) {
            list($assoc_url, $_) = unserialize($key);
            $pairs[] = array($assoc_url, $assoc);
        }
        return $pairs;
    }

    function getServerAssocs($server_url)
    {
        $matches = array();
        foreach ($this->getAssocPairs() as $pair) {
            list($assoc_url, $assoc) = $pair;
            if ($assoc_url == $server_url) {
                $matches[] = $assoc;
            }
        }
        return $matches;
    }

    function getAssociation($server_url, $handle=null)
    {
        $assocs = $this->getServerAssocs($server_url);
        if ($handle === null) {
            $best = null;
            foreach ($assocs as $assoc) {
                if (!isset($best) ||
                    $best->issued < $assoc->issued) {

                    $best = $assoc;
                }
            }
            return $best;
        } else {
            foreach ($assocs as $assoc) {
                if ($assoc->handle == $handle) {
                    return $assoc;
                }
            }
            return null;
        }
    }

    function storeAssociation($server_url, &$association)
    {
        $key = $this->getKey($server_url, $association->handle);
        $this->assocs[$key] = $association;
    }

    function removeAssociation($server_url, $handle)
    {
        $key = $this->getKey($server_url, $handle);
        $present = isset($this->assocs[$key]);
        unset($this->assocs[$key]);
        return $present;
    }

    function storeNonce($nonce)
    {
        if (!in_array($nonce, $this->nonces)) {
            $this->nonces[] = $nonce;
        }
    }

    function useNonce($nonce)
    {
        $index = array_search($nonce, $this->nonces);
        $present = $index !== false;
        if ($present) {
            unset($this->nonces[$index]);
        }
        return $present;
    }

    function reset()
    {
        $this->assocs = array();
        $this->nonces = array();
    }

    function getAuthKey()
    {
        return $this->auth_key;
    }
}