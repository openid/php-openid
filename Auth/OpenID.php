<?php

/**
 * This is the PHP OpenID library by JanRain, Inc.
 *
 * This module contains core utility functionality used by the
 * library.  See Consumer.php and Server.php for the consumer and
 * server implementations.
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
 * Detect the presence of Curl and set a flag accordingly.
 */
define('Auth_OpenID_CURL_PRESENT', function_exists('curl_init'));

class Auth_OpenID {

    /**
     * Factory function that will return an instance of the
     * appropriate HTTP fetcher
     */
    function getHTTPFetcher()
    {
        if (defined('Auth_OpenID_CURL_PRESENT') &&
            Auth_OpenID_CURL_PRESENT) {
            $fetcher = new Auth_OpenID_ParanoidHTTPFetcher();
        } else {
            $fetcher = new Auth_OpenID_PlainHTTPFetcher();
        }
        return $fetcher;
    }
}

?>