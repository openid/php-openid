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
        $url = getServerURL();
    }
    return redirect_render($url);
}

function doAuth($info, $trusted=null, $fail_cancels=false)
{
    if (!$info) {
        // There is no authentication information, so bail
        return authCancel(null);
    }

    $req_url = $info->identity;
    $user = getLoggedInUser();
    setRequestInfo($info);

    if ($req_url != $user) {
        return login_render(array(), $req_url, $req_url);
    }

    $sites = getSessionSites();
    $trust_root = $info->trust_root;
    $fail_cancels = $fail_cancels || isset($sites[$trust_root]);
    $trusted = isset($trusted) ? $trusted : isTrusted($req_url, $trust_root);
    if ($trusted) {
        setRequestInfo();
        $server =& getServer();
        $response =& $info->answer(true);
        $webresponse =& $server->encodeResponse($response);

        $new_headers = array();

        foreach ($webresponse->headers as $k => $v) {
            $new_headers[] = $k.": ".$v;
        }

        return array($new_headers, $webresponse->body);
    } elseif ($fail_cancels) {
        return authCancel($info);
    } else {
        return trust_render($info);
    }
}

?>