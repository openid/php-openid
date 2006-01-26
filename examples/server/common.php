<?php

$path_extra = dirname(dirname(dirname(__FILE__)));
$path = ini_get('include_path');
$path = $path_extra . ':' . $path;
ini_set('include_path', $path);

require_once "Auth/OpenID/Server.php";
require_once "Auth/OpenID/Store/FileStore.php";

define('DEFAULT_STORE_DIR', '/tmp/php_example_store');

function serverRootURL()
{
    $server = $_SERVER['SERVER_NAME'];
    $req_port = $_SERVER['SERVER_PORT'];

    list($proto, $_) = explode('/', $_SERVER['SERVER_PROTOCOL'], 2);
    $proto = strtolower($proto);

    if ($proto != 'http') {
        trigger_error("I don't know how to build a URL for $proto",
                      E_USER_WARNING);
        return false;
    }

    if (isset($_SERVER["HTTPS"]) && $_SERVER["HTTPS"] == "on") {
        $proto .= 's';
        $default_port = '443';
    } else {
        $default_port = '80';
        $port = ($req_port == '443') ? '' : (':' . $req_port);
    }

    $port = ($req_port == $default_port) ? "" : (":" . $req_port);

    $pat = "%s://%s%s";
    return sprintf($pat, $proto, $server, $port);
}

function getCurrentURL($full=false)
{
    $tail = $full ? $_SERVER['REQUEST_URI'] : $_SERVER['SCRIPT_NAME'];
    return serverRootURL() . $tail;
}

function getParentURL()
{
    return serverRootURL() . dirname($_SERVER['SCRIPT_NAME']);
}

function relURL($path)
{
    if (substr($path, 0, 1) != '/') {
        $path = '/' . $path;
    }
    return getParentURL() . $path;
}

function newServer($store_dir=DEFAULT_STORE_DIR, $server_url=null)
{
    if (!isset($server_url)) {
        $server_url = getParentURL();
    }
    if (!file_exists($store_dir) && !mkdir($store_dir)) {
        print "Could not create the FileStore directory '$store_path'. ".
            " Please check the effective permissions.";
        exit(0);
    }

    $store = new Auth_OpenID_FileStore($store_dir);
    return new Auth_OpenID_Server($server_url, &$store);
}

function returnKV($kv)
{
    header('Content-Type: text/plain; charset=us-ascii');
    print $kv;
}

function redirect($redir_url)
{
    header('Location: ' . $redir_url);
    header('Content-Type: text/plain; charset=us-ascii');
    print 'Please wait; you are being redirected to ' . $redir_url;
}

function showError($error, $status, $message)
{
    header('HTTP/1.1 ' . $status . ' ' . $message);
    header('Content-Type: text/plain; charset=us-ascii');
    print "An error occurred when processing your request:\n$error\n\n";
    var_export($_SERVER);
}

function linkURL($url) {
    $esc_url = htmlspecialchars($url, ENT_QUOTES);
    return "<a href='$esc_url'>$esc_url</a>";
}
    
$parent = getParentURL();
$success_identity = relURL('success.php');
$failure_identity = relURL('failure.php');
$server_url = relURL('server.php');

$esc_server = htmlspecialchars($server_url, ENT_QUOTES);
$esc_success = htmlspecialchars($success_identity, ENT_QUOTES);
$esc_failure = htmlspecialchars($failure_identity, ENT_QUOTES);
?>