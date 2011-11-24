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
 * @copyright 2010 JanRain, Inc. isamu arimoto.
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
        $associationKey = $this->associationKey($server_url, $association->handle);

        try{
            // save association itself
            $this->connection->put(
                                   $associationKey,
                                   array(
                                         "server_url" => $server_url,
                                         "issued" => $association->issued,
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
        $query = $this->connection->getQuery();
        $query->addCond("server_url", TokyoTyrant::RDBQC_STREQ, $server_url);
        $query->setOrder("issued", TokyoTyrant::RDBQO_NUMDESC);
        $query->setLimit(1);
        $associations = $query->search();
        // return null if failed or got empty list
        if(!$associations){
            return null;
        }
        // get association, return null if failed
        $association = array_pop($associations);
        return $association ? (unserialize($association['association'])) : null;
    }

    /**
     * Immediately delete association from TokyoTyrantTable.
     */
    function removeAssociation($server_url, $handle)
    {
        // create TokyoTyrantTable keys for association itself 
        $associationKey = $this->associationKey($server_url, 
            $handle);
        
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
        
        // save one request to TokyoTyrantTable when nonce obviously expired 
        if (abs($timestamp - time()) > $Auth_OpenID_SKEW) {
            return false;
        }
        
        // returns false when nonce already exists
        // otherwise adds nonce
        try{
            return $this->connection->putKeep(
                                              'openid_nonce_' . $server_url . '_' . $timestamp . '_' . $salt,
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

