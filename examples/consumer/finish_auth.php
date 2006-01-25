<?php

require_once "common.php";
session_start();

// Retrieve the token from the session so we can verify the server's
// response.
$token = $_SESSION['openid_token'];

// Complete the authentication process using the server's response.
list($status, $info) = $consumer->completeAuth($token, $_GET);

$openid = null;

// React to the server's response.  $info is the OpenID that was
// tried.
if ($status != Auth_OpenID_SUCCESS) {
    $msg = sprintf("Verification of %s failed.", $info);
} else {
    if ($info) {
        // This means the authentication succeeded.
        $openid = $info;
        $success = sprintf("You have successfully verified %s as your identity.",
                       $openid);
    } else {
        // This means the authentication was ancelled.
        $msg = 'Verification cancelled.';
    }
}

include 'index.php';

?>