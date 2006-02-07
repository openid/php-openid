<?php
/**
 * OpenID server example settings
 *
 * The variables in this file must be customized before you can use
 * the server.
 *
 * @package OpenID.Examples
 * @author JanRain, Inc. <openid@janrain.com>
 * @copyright 2005 Janrain, Inc.
 * @license http://www.gnu.org/copyleft/lesser.html LGPL
 */

/**
 * Set any extra include paths needed to use the library
 */
//$path_extra = dirname(dirname(dirname(__FILE__)));
//$path = ini_get('include_path');
//$path = $path_extra . ':' . $path;
//ini_set('include_path', $path);

/**
 * The URL for the server.
 *
 * This is the location of server.php. For example:
 *
 * $server_url = 'http://example.com/~user/server.php';
 *
 * This must be a full URL.
 */
$server_url = false;

/**
 * Initialize an OpenID store
 *
 * @return object $store an instance of OpenID store (see the
 * documentation for how to create one)
 */
function getOpenIDStore()
{
    return false;
}

/**
 * Users who are allowed to log in to this OpenID server.
 *
 * This is an array from URL to password hash. The URL must include
 * the proper OpenID server information in order to work with this
 * server.
 *
 * This must be set for the server to be usable. If it is not set, no
 * users will be able to log in.
 */
$openid_users = false;

/**
 * Trusted sites is an array of trust roots.
 *
 * Sites in this list will not have to be approved by the user in
 * order to be used. It is OK to leave this value as-is.
 *
 * In a more robust server, this site should be a per-user setting.
 */
$trusted_sites = array();
?>