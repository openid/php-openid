<?php

/**
 * In-memory OpenID store implementation for testing only
 */
require_once "Auth/OpenID/Interface.php";

class Tests_Auth_OpenID_MemStore extends Auth_OpenID_OpenIDStore {
    var $assocs = null;
    var $nonces = null;

    function Tests_Auth_OpenID_MemStore()
    {
        $this->assocs = array();
        $this->nonces = array();
    }

    function getKey($server_url, $handle)
    {
        return serialize(array($server_url, $handle));
    }

    function getBest($assoc_list)
    {
        $best = null;
        foreach ($assoc_list as $assoc) {
            if (($best === null) ||
                ($best->issued < $assoc->issued)) {
                $best = $assoc;
            }
        }
        return $best;
    }

    function getExpired()
    {
        $expired = array();
        foreach ($this->assocs as $url => $assocs) {
            $best = $this->getBest($assocs);
            if (($best === null) ||
                ($best->getExpiresIn() == 0)) {
                $expired[] = $server_url;
            }
        }

        return $expired;
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

    function useNonce($server_url, $timestamp, $salt)
    {
        $nonce = sprintf("%s%s%s", $server_url, $timestamp, $salt);
        if (in_array($nonce, $this->nonces)) {
            return false;
        } else {
            $this->nonces[] = $nonce;
            return true;
        }
    }

    function reset()
    {
        $this->assocs = array();
        $this->nonces = array();
    }
}