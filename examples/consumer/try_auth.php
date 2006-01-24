<?php

require_once "common.php";
session_start();

// Render a default page if we got a submission without an openid
// value.
if (!array_key_exists('openid_url', $_GET) ||
    !$_GET['openid_url']) {
    print "Expected an OpenID URL.";
    exit(0);
}

$openid = $_GET['openid_url'];
$process_url = sprintf("http://%s%s/finish_auth.php",
                       $_SERVER['SERVER_NAME'],
                       dirname($_SERVER['PHP_SELF']));

$trust_root = sprintf("http://%s%s",
                      $_SERVER['SERVER_NAME'],
                      dirname($_SERVER['PHP_SELF']));

// Begin the OpenID authentication process.
list($status, $info) = $consumer->beginAuth($openid);

// Handle failure status return values.
if ($status != Auth_OpenID_SUCCESS) {
    print "Authentication error.";
    exit(0);
}

// If we got a successful return, continue the auth by redirecting the
// user agent to the OpenID server.  Be sure to give the server a URL
// that will cause this script's "process" function to process the
// server's response.
$_SESSION['openid_token'] = $info->token;
$redirect_url = @$consumer->constructRedirect($info, $process_url,
                                              $trust_root);

header("Location: ".$redirect_url);

?>