<?php

require_once "common.php";
session_start();

// Render a default page if we got a submission without an openid
// value.
if (empty($_GET['openid_url'])) {
    $error = "Expected an OpenID URL.";
    include 'index.php';
    exit(0);
}

$scheme = 'http';
if (isset($_SERVER['HTTPS']) and $_SERVER['HTTPS'] == 'on') {
    $scheme .= 's';
}

$openid = $_GET['openid_url'];
$process_url = sprintf("$scheme://%s:%s%s/finish_auth.php",
                       $_SERVER['SERVER_NAME'], $_SERVER['SERVER_PORT'],
                       dirname($_SERVER['PHP_SELF']));

$trust_root = sprintf("$scheme://%s:%s%s",
                      $_SERVER['SERVER_NAME'], $_SERVER['SERVER_PORT'],
                      dirname($_SERVER['PHP_SELF']));

// Begin the OpenID authentication process.
$auth_request = $consumer->begin($openid);

// Handle failure status return values.
if (!$auth_request) {
    $error = "Authentication error.";
    include 'index.php';
    exit(0);
}

$auth_request->addExtensionArg('sreg', 'optional', 'email');

// Redirect the user to the OpenID server for authentication.  Store
// the token for this authentication so we can verify the response.

$redirect_url = $auth_request->redirectURL($trust_root,
                                           $process_url);

header("Location: ".$redirect_url);

?>