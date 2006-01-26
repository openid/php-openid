<?php

require_once "common.php";

$server = newServer();

function isAuthorized($identity_url, $trust_root) {
    global $success_identity;
    return ($identity_url === $success_identity);
}

list($status, $info) = $server->getOpenIDResponse('isAuthorized');

switch($status) {
case Auth_OpenID_REMOTE_ERROR:
case Auth_OpenID_REMOTE_OK:
    returnKV($info);
    return;
case Auth_OpenID_REDIRECT:
    redirect($info);
    return;
case Auth_OpenID_DO_AUTH:
    redirect($info->getCancelURL());
case Auth_OpenID_DO_ABOUT:
    include "about.php";
    return;
case Auth_OpenID_LOCAL_ERROR:
    showError($info, '400', 'Bad request');
    return;
default:
    $error = "Internal error: unknown status $status";
    showError($error, '500', 'Internal error');
    return;
}
?>