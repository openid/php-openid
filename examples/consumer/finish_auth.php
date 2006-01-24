<?php

require_once "common.php";
session_start();

// Retrieve the token from the session.
$token = $_SESSION['openid_token'];

// Complete the authentication process using the server's response.
list($status, $info) = $consumer->completeAuth($token, $_GET);

$openid = null;

// React to the server's response.  $info is the OpenID that was
// tried.
if ($status != Auth_OpenID_SUCCESS) {
    print sprintf("Verification of %s failed.", $info);
    exit(0);
}

// The OpenID authentication either succeeded or was cancelled by the
// user.
if ($info) {
    // This means the authentication succeeded.
    $openid = $info;
    print sprintf("You have successfully verified %s as your identity.",
                  $openid);
} else {
    // Cancelled.
    print 'Verification cancelled.';
}

?>