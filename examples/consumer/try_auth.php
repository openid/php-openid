<?php

require_once "common.php";
session_start();

function getOpenIDURL() {
    // Render a default page if we got a submission without an openid
    // value.
    if (empty($_GET['openid_url'])) {
        $error = "Expected an OpenID URL.";
        include 'index.php';
        exit(0);
    }

    return $_GET['openid_url'];
}

function getScheme() {
    $scheme = 'http';
    if (isset($_SERVER['HTTPS']) and $_SERVER['HTTPS'] == 'on') {
        $scheme .= 's';
    }
    return $scheme;
}

function getReturnTo() {
    return sprintf("%s://%s:%s%s/finish_auth.php",
                   getScheme(), $_SERVER['SERVER_NAME'],
                   $_SERVER['SERVER_PORT'],
                   dirname($_SERVER['PHP_SELF']));
}

function getTrustRoot() {
    return sprintf("%s://%s:%s%s/",
                   getScheme(), $_SERVER['SERVER_NAME'],
                   $_SERVER['SERVER_PORT'],
                   dirname($_SERVER['PHP_SELF']));
}

function run() {
    $openid = getOpenIDURL();
    $consumer = getConsumer();

    // Begin the OpenID authentication process.
    $auth_request = $consumer->begin($openid);

    // Handle failure status return values.
    if (!$auth_request) {
        displayError("Authentication error; not a valid OpenID.");
    }

    $auth_request->addExtensionArg('sreg', 'optional', 'email');

    // Redirect the user to the OpenID server for authentication.
    // Store the token for this authentication so we can verify the
    // response.

    if ($auth_request->shouldSendRedirect()) {
        $redirect_url = $auth_request->redirectURL(getTrustRoot(),
                                                   getReturnTo());

        if (Auth_OpenID::isFailure($redirect_url)) {
            displayError("Could not redirect to server: " . $redirect_url->message);
        } else {
            header("Location: ".$redirect_url);
        }
    } else {
        $form_id = 'openid_message';
        $form_html = $auth_request->formMarkup(getTrustRoot(), getReturnTo(),
                                               false, array('id' => $form_id));

        if (Auth_OpenID::isFailure($form_html)) {
            displayError("Could not redirect to server: " . $form_html->message);
        } else {
            $page_contents = array(
               "<html><head><title>",
               "OpenID transaction in progress",
               "</title></head>",
               "<body onload='document.getElementById(\"<?=$form_id?>\").submit()'>",
               $form_html,
               "</body></html>");

            print implode("\n", $page_contents);
        }
    }
}

run();

?>