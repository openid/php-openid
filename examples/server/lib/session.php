<?php

require_once "config.php";
require_once "Auth/OpenID/Server.php";

/**
 * Set up the session
 */
function init()
{
    session_name('openid_server');
    session_start();
}

/**
 * Get the style markup
 */
function getStyle()
{
    global $style;
    return $style;
}

/**
 * Build a URL to a server action
 */
function buildURL($action=null, $escaped=true)
{
    // from config.php
    global $server_url;

    $url = $server_url;
    if ($action) {
        $url .= '/' . $action;
    }
    return $escaped ? htmlspecialchars($url, ENT_QUOTES) : $url;
}

/**
 * Extract the current action from the request
 */
function getAction()
{
    $path_info = @$_SERVER['PATH_INFO'];
    $action = ($path_info) ? substr($path_info, 1) : '';
    $function_name = 'action_' . $action;
    return $function_name;
}

/**
 * Write the response to the request
 */
function writeResponse($resp)
{
    list ($headers, $body) = $resp;
    array_walk($headers, 'header');
    print $body;
}

/**
 * Instantiate a new OpenID server object
 */
function getServer()
{
    // from config.php
    global $server_url;

    static $server = null;
    if (!isset($server)) {
        $server = new Auth_OpenID_Server($server_url, getOpenIDStore());
    }
    return $server;
}

/**
 * Return whether the trust root is currently trusted
 */
function isTrusted($trust_root)
{
    // from config.php
    global $trusted_sites;
    if (in_array($trust_root, $trusted_sites)) {
        return true;
    }
    $sites = getSessionSites();
    return isset($sites[$trust_root]) && $sites[$trust_root];
}

/**
 * Return a hashed form of the user's password
 */
function hashPassword($password)
{
    return bin2hex(Auth_OpenID_SHA1($password));
}

/**
 * Check the user's login information
 */
function checkLogin($openid_url, $password)
{
    // from config.php
    global $openid_users;
    $hash = hashPassword($password);

    return isset($openid_users[$openid_url])
        && $hash == $openid_users[$openid_url];
}

/**
 * Get the openid_url out of the cookie
 *
 * @return mixed $openid_url The URL that was stored in the cookie or
 * false if there is none present or if the cookie is bad.
 */
function getLoggedInUser()
{
    return isset($_SESSION['openid_url'])
        ? $_SESSION['openid_url']
        : false;
}

/**
 * Set the openid_url in the cookie
 *
 * @param mixed $identity_url The URL to set. If set to null, the
 * value will be unset.
 */
function setLoggedInUser($identity_url=null)
{
    if (!isset($identity_url)) {
        unset($_SESSION['openid_url']);
    } else {
        $_SESSION['openid_url'] = $identity_url;
    }
}

function setSessionSites($sites=null)
{
    if (!isset($sites)) {
        unset($_SESSION['session_sites']);
    } else {
        $_SESSION['session_sites'] = serialize($sites);
    }
}

function getSessionSites()
{
    return isset($_SESSION['session_sites'])
        ? unserialize($_SESSION['session_sites'])
        : false;
}

function getRequestInfo()
{
    return isset($_SESSION['request'])
        ? unserialize($_SESSION['request'])
        : false;
}

function setRequestInfo($info=null)
{
    if (!isset($info)) {
        unset($_SESSION['request']);
    } else {
        $_SESSION['request'] = serialize($info);
    }
}

?>