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

$openid = $_GET['openid_url'];
$process_url = sprintf("http://%s%s/finish_auth.php",
                       $_SERVER['SERVER_NAME'],
                       dirname($_SERVER['PHP_SELF']));

$trust_root = sprintf("http://%s%s",
                      $_SERVER['SERVER_NAME'],
                      dirname($_SERVER['PHP_SELF']));

// Begin the OpenID authentication process.
list($status, $info) = @$consumer->beginAuth($openid);

// Handle failure status return values.
if ($status != Auth_OpenID_SUCCESS) {
    $error = "Authentication error.";
    include 'index.php';
    exit(0);
}

// Redirect the user to the OpenID server for authentication.  Store
// the token for this authentication so we can verify the response.
$_SESSION['openid_token'] = $info->token;
$redirect_url = @$consumer->constructRedirect($info, $process_url,
                                              $trust_root);

header("Location: ".$redirect_url);

?>