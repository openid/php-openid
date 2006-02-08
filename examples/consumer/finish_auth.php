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
        $esc_identity = htmlspecialchars($openid, ENT_QUOTES);
        $success = sprintf('You have successfully verified ' .
                           '<a href="%s">%s</a> as your identity.',
                           $esc_identity,
                           $esc_identity
                           );
    } else {
        // This means the authentication was cancelled.
        $msg = 'Verification cancelled.';
    }
}

include 'index.php';

?>