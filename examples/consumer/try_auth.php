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

if ($auth_request->shouldSendRedirect()) {
    $redirect_url = $auth_request->redirectURL($trust_root,
                                               $process_url);
    header("Location: ".$redirect_url);
} else {
    $form_id = 'openid_message';
    $form_html = $auth_request->formMarkup($trust_root, $process_url, false,
                                           $form_tag_attrs=array('id' => $form_id));

    if (is_a($form_html, 'Auth_OpenID_FailureResponse')) {
        print "Error: " . $form_html->message;
    }

?>
<html><head><title>OpenID transaction in progress</title></head>
<body onload='document.getElementById("<?=$form_id?>").submit()'>
<?=$form_html?>
</body></html>
<?
}

?>