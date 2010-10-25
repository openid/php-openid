<?php

/**
 * This file supplies a TokyoTyrantTable store backend for OpenID servers and
 * consumers.
 *
 * PHP versions 4 and 5
 *
 * LICENSE: See the COPYING file included in this distribution.
 *
 * @package OpenID
 * @author isamu arimoto <git@isamu.cc>
 * @copyright 2010 JanRain, Inc.
 * @license http://www.apache.org/licenses/LICENSE-2.0 Apache
 * Contributed by Open Web Technologies <http://openwebtech.ru/>
 */

/**
 * important notice
 * Pecl-TokyoTyrantTable has bug.
 * Use git version of Pecl-TokyoTyrantTable.
 */

/**
 * Import the interface for creating a new store class.
 */
require_once 'Auth/OpenID/Interface.php';

/**
 * This is a TokyoTyrantTable-based store for OpenID associations and
 * nonces. 
 * 
 * server_url, handle and salt are hashed with sha1(). 
 *
 * Most of the methods of this class are implementation details.
 * People wishing to just use this store need only pay attention to
 * the constructor.
 *
 * @package OpenID
 */
class Auth_OpenID_TokyoTyrantTableStore extends Auth_OpenID_OpenIDStore {

    /**
     * Initializes a new {@link Auth_OpenID_TokyoTyrantTableStore} instance.
     * Just saves TokyoTyrantTable object as property.
     *
     * @param resource connection TokyoTyrantTable connection resourse
     */
    function Auth_OpenID_TokyoTyrantTableStore($connection)
    {
        $this->connection = $connection;
    }

    /**
     * Store association until its expiration time in TokyoTyrantTable. 
     * Overwrites any existing association with same server_url and 
     * handle. Handles list of associations for every server. 
     */
    function storeAssociation($server_url, $association)
    {
        // create TokyoTyrantTable keys for association itself 
        // and list of associations for this server
        $associationKey = $this->associationKey($server_url, 
            $association->handle);
        $serverKey = $this->associationServerKey($server_url);
        
        // get list of associations 
        $serverAssociations = $this->connection->get($serverKey);
        
        // if no such list, initialize it with empty array
        if (!$serverAssociations) {
            $serverAssociations = array();
        }
        // and store given association key in it
        $serverAssociations[strval($association->issued)] = $associationKey;

        try{
            // save associations' keys list 
            $this->connection->put(
                                   $serverKey,
                                   $serverAssociations
                                   );
            // save association itself
            $this->connection->put(
                                   $associationKey,
                                   array(
                                         "server_url" => $server_url,
                                         "association" => serialize($association),
                                         "association_expire" => $association->issued +  $association->lifetime ));
        }catch (TokyoTyrantException $e){
            trigger_error("TokyoTyrantTableStore no longer active", E_USER_ERROR);
        }
    }

    /**
     * Read association from TokyoTyrantTable. If no handle given 
     * and multiple associations found, returns latest issued
     */
    function getAssociation($server_url, $handle = null)
    {
        // simple case: handle given
        if ($handle !== null) {
            // get association, return null if failed
            $association = $this->connection->get(
                $this->associationKey($server_url, $handle));
            return $association ? (unserialize($association['association'])) : null;
        }
        
        // no handle given, working with list
        // create key for list of associations
        $serverKey = $this->associationServerKey($server_url);
        
        // get list of associations
        $serverAssociations = $this->connection->get($serverKey);
        // return null if failed or got empty list
        if (!$serverAssociations) {
            return null;
        }
        
        // get key of most recently issued association
        $keys = array_keys($serverAssociations);
        sort($keys);
        $lastKey = $serverAssociations[array_pop($keys)];
        // get association, return null if failed
        $association = $this->connection->get($lastKey);
        return $association ? (unserialize($association['association'])) : null;
    }

    /**
     * Immediately delete association from memcache.
     */
    function removeAssociation($server_url, $handle)
    {
        // create TokyoTyrantTable keys for association itself 
        // and list of associations for this server
        $serverKey = $this->associationServerKey($server_url);
        $associationKey = $this->associationKey($server_url, 
            $handle);
        
        // get list of associations
        $serverAssociations = $this->connection->get($serverKey);
        // return null if failed or got empty list
        if (!$serverAssociations) {
            return false;
        }
        
        // ensure that given association key exists in list
        $serverAssociations = array_flip($serverAssociations);
        if (!array_key_exists($associationKey, $serverAssociations)) {
            return false;
        }
        
        // remove given association key from list
        unset($serverAssociations[$associationKey]);
        $serverAssociations = array_flip($serverAssociations);
        
        // save updated list
        $this->connection->put(
            $serverKey,
            $serverAssociations
        );

        // delete association 
        return $this->connection->out($associationKey);
    }

    /**
     * Create nonce for server and salt, expiring after 
     * $Auth_OpenID_SKEW seconds.
     */
    function useNonce($server_url, $timestamp, $salt)
    {
        global $Auth_OpenID_SKEW;
        
        // save one request to memcache when nonce obviously expired 
        if (abs($timestamp - time()) > $Auth_OpenID_SKEW) {
            return false;
        }
        
        // returns false when nonce already exists
        // otherwise adds nonce
        try{
            return $this->connection->putKeep(
                                              'openid_nonce_' . $server_url . '_' . $salt,
                                              array("nonce_expire" => time() + $Auth_OpenID_SKEW));
        }catch (TokyoTyrantException $e){
            return false;
        }
    }
    
    /**
     * TokyoTyrantTable key is prefixed with 'openid_association_' string. 
     */
    function associationKey($server_url, $handle = null) 
    {
        return 'openid_association_' . $server_url . '_' . $handle;
    }
    
    /**
     * TokyoTyrantTable key is prefixed with 'openid_association_' string. 
     */
    function associationServerKey($server_url) 
    {
        return 'openid_association_server_' . $server_url;
    }
    
    function cleanupNonces()
    {
        $query = $this->connection->getQuery();
        $query->addCond("nonce_expire", TokyoTyrant::RDBQC_NUMLT, time());
        return $query->out();
    }

    function cleanupAssociations()
    {
        $query = $this->connection->getQuery();
        $query->addCond("association_expire", TokyoTyrant::RDBQC_NUMLT, time());
        return $query->out();
    }

}

