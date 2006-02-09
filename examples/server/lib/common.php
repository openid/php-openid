<?php

require_once "lib/render.php";
require_once "lib/session.php";

require_once "lib/render/login.php";
require_once "lib/render/about.php";
require_once "lib/render/trust.php";

require_once "Auth/OpenID/Server.php";
require_once "Auth/OpenID/HMACSHA1.php";

function authCancel($info)
{
    if ($info) {
        setRequestInfo();
        $url = $info->getCancelURL();
    } else {
        $server = getServer();
        $url = $server->server_url;
    }
    return redirect_render($url);
}

function handleResponse($response, $do_auth=true)
{
    list ($status, $info) = $response;
    switch($status) {
    case Auth_OpenID_REMOTE_ERROR:
        return kv_render($info, false);
    case Auth_OpenID_REMOTE_OK:
        return kv_render($info);
    case Auth_OpenID_REDIRECT:
        return redirect_render($info);
    case Auth_OpenID_DO_AUTH:
        if ($do_auth) {
            return doAuth($info);
        } else {
            return about_render('Got unexpected DO_AUTH');
        }
    case Auth_OpenID_DO_ABOUT:
        return about_render();
    case Auth_OpenID_LOCAL_ERROR:
        return about_render($info, false);
    default:
        $repr = var_export($status, true);
        return about_render("Internal error: unknown status $repr");
    }
}

function doAuth($info, $trusted=null, $fail_cancels=false)
{
    if (!$info) {
        // There is no authentication information, so bail
        return authCancel(null);
    }

    $req_url = $info->getIdentityURL();
    $user = getLoggedInUser();
    setRequestInfo($info);

    if ($req_url != $user) {
        return login_render(array(), $req_url, $req_url);
    }

    $sites = getSessionSites();
    $trust_root = $info->getTrustRoot();
    $fail_cancels = $fail_cancels || isset($sites[$trust_root]);
    $trusted = isset($trusted) ? $trusted : isTrusted($req_url, $trust_root);
    if ($trusted) {
        setRequestInfo();
        $server = getServer();
        $response = $server->getAuthResponse(&$info, true);
        return handleResponse($response, false);
    } elseif ($fail_cancels) {
        return authCancel($info);
    } else {
        return trust_render($info);
    }
}

?>