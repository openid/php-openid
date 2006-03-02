<?php
/**
 * This module contains the HTTP fetcher interface
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
 * Require the parser and OpenID util functions.
 */
require_once "Auth/OpenID/Parse.php";
require_once "Auth/OpenID.php";

/**
 * This is the status code beginAuth returns when it is unable to
 * fetch the OpenID URL the user entered.
 */
define('Auth_OpenID_HTTP_FAILURE', 'http failure');

/**
 * The maximum allowed timeout for fetcher operations.
 */
define('Auth_OpenID_FETCHER_TIMEOUT', 20);

/**
 * This class is the interface for HTTP fetchers the OpenID consumer
 * library uses.  This interface is only important if you need to
 * write a new fetcher for some reason.
 *
 * @access private
 * @package OpenID
 */
class Auth_OpenID_HTTPFetcher {

    /**
     * Allowed socket timeout in seconds.
     */
    var $timeout = Auth_OpenID_FETCHER_TIMEOUT;

    /**
     * Return whether a URL should be allowed. Override this method to
     * conform to your local policy.
     *
     * By default, will attempt to fetch any http or https URL.
     */
    function allowedURL($url)
    {
        return $this->URLHasAllowedScheme($url);
    }

    /**
     * Is this an http or https URL?
     *
     * @access private
     */
    function URLHasAllowedScheme($url)
    {
        return (bool)preg_match('/^https?:\/\//i', $url);
    }

    /**
     * @access private
     */
    function _findRedirect($headers)
    {
        foreach ($headers as $line) {
            if (strpos($line, "Location: ") === 0) {
                $parts = explode(" ", $line, 2);
                return $parts[1];
            }
        }
        return null;
    }

    /**
     * This performs an HTTP get, following redirects along the way.
     *
     * @return array $tuple This returns a three-tuple on success.
     * The first value is the http return code. The second value is
     * the final url that was fetched, after following any redirects.
     * The third value is the data that was retrieved from the site.
     * If the fetch didn't succeed, return null.
    */
    function get($url)
    {
        trigger_error("not implemented", E_USER_ERROR);
    }

    /**
     * This performs an HTTP post.  If it makes sense, it will follow
     * redirects along the way.
     *
     * @return array $tuple This returns a three-tuple on success.
     * The first value is the http return code. The second value is
     * the final url that was fetched, after following any redirects.
     * The third value is the data that was retrieved from the site.
     * If the fetch didn't succeed, return null.
     */
    function post($url, $body)
    {
        trigger_error("not implemented", E_USER_ERROR);
    }

    /**
     * Retrieve the given URL and return the identity information
     * contained therein. That is, perform OpenID discovery.
     *
     * @param string $identity_url The URL that the user entered
     *
     * @return array list($status, $info) The information parsed from
     * the page or an error. If the status is {@link Auth_OpenID_SUCCESS},
     * the information returned is array($consumer_id, $server_id,
     * $server_url). The $server_url is the OpenID server's URL. The
     * consumer ID is the identifier by which the user should be known
     * to the consumer. The server ID is the identifier by which the
     * user should be known to the server.
     */
    function findIdentityInfo($identity_url)
    {
        $url = Auth_OpenID::normalizeURL($identity_url);
        $ret = @$this->get($url);
        if ($ret === null) {
            return array(Auth_OpenID_HTTP_FAILURE, null);
        }

        list($http_code, $consumer_id, $data) = $ret;
        if ($http_code != 200) {
            return array(Auth_OpenID_HTTP_FAILURE, $http_code);
        }

        $parser = new Auth_OpenID_Parse();

        $link_attrs = $parser->parseLinkAttrs($data);
        $server = $parser->findFirstHref($link_attrs, 'openid.server');
        $delegate = $parser->findFirstHref($link_attrs, 'openid.delegate');

        if ($server === null) {
            return array(Auth_OpenID_PARSE_ERROR, null);
        } else {
            $server_id = $delegate ? $delegate : $consumer_id;
            $urls = array($consumer_id, $server_id, $server);
            return array(Auth_OpenID_SUCCESS, $urls);
        }
    }
}

?>