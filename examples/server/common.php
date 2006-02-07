<?php

require_once "config.php";
require_once "Auth/OpenID/Server.php";
require_once "Auth/OpenID/HMACSHA1.php";

/**
 * Instantiate a new OpenID server object
 */
function getServer()
{
    global $server_url;
    static $server = null;
    if (!isset($server)) {
        $server = new Auth_OpenID_Server($server_url, getOpenIDStore());
    }
    return $server;
}

/**
 * Respond to an OpenID consumer POST request
 */
function returnKV($kv, $success=true)
{
    if (!$success) {
        header('400 Bad Request');
    }
    header('Content-Type: text/plain; charset=us-ascii');
    print $kv;
}

/**
 * Perform an HTTP redirect
 */
function redirect($redir_url)
{
    header('HTTP/1.1 302 Found');
    header('Location: ' . $redir_url);
    header('Content-Type: text/plain; charset=us-ascii');
    print 'Please wait; you are being redirected to ' . $redir_url;
}

/**
 * Display an error page
 */
function showError($error, $status, $message)
{
    header('HTTP/1.1 ' . $status . ' ' . $message);
    header('Content-Type: text/plain; charset=us-ascii');
    print "An error occurred when processing your request:\n$error\n";
}

/**
 * Return a string containing an anchor tag containing the given URL
 *
 * The URL does not need to be quoted, but if text is passed in, then
 * it does.
 */
function linkURL($url, $text=null) {
    $esc_url = htmlspecialchars($url, ENT_QUOTES);
    if ($text === null) {
        $text = $esc_url;
    }
    return "<a href='$esc_url'>$text</a>";
}

function hashPassword($password)
{
    return bin2hex(Auth_OpenID_SHA1($password));
}

/**
 * Set up the session
 */
function init()
{
    session_name('openid_server');
    session_start();
}

/**
 * Check the user's login information
 */
function checkLogin($openid_url, $password)
{
    global $openid_users;
    $hash = hashPassword($password);

    return isset($openid_users[$openid_url])
        && $hash == $openid_users[$openid_url];
}

/**
 * Get the openid_url out of the cookie
 *
 * @return mixed $openid_url The URL that was stored in the cookie or
 * false if there is none present or if the cookie is bad.
 */
function getLoggedInUser()
{
    return isset($_SESSION['openid_url'])
        ? $_SESSION['openid_url']
        : false;
}

/**
 * Set the openid_url in the cookie
 *
 * @param mixed $identity_url The URL to set. If set to null, the
 * value will be unset.
 */
function setLoggedInUser($identity_url=null)
{
    if (!isset($identity_url)) {
        unset($_SESSION['openid_url']);
    } else {
        $_SESSION['openid_url'] = $identity_url;
    }
}

function pageHeader($user, $title, $h1=null, $login=false)
{
    if (!$h1) {
        $h1 = $title;
    }

    if ($user) {
        $head = sprintf(logged_in_pat, linkURL($user));
    } else {
        if (!$login) {
            $head = logged_out_pat;
        }
    }

    return sprintf(html_start, $title, $h1, $head);
}

function pageFoot()
{
    return html_end;
}

function succeed($info)
{
    $server = getServer();
    $resp = $server->getAuthResponse(&$info, true);
    handleResponse($resp, 'badAuth');
}

function doAuth($info)
{
    $req_url = $info->getIdentityURL();
    $user = getLoggedInUser();
    if ($req_url == $user) {
        if (isTrusted($info->getTrustRoot())) {
            // This is a trusted site, so continue
            succeed($info);
        } else {
            $_SESSION['request'] = serialize($info);
            trustPage($info);
        }
    } else {
        $_SESSION['request'] = serialize($info);
        if ($user) {
            $msg = sprintf(bad_user_pat, linkURL($user), linkURL($req_url));
        } else {
            $msg = sprintf(no_user_pat, linkURL($req_url));
        }
        loginPage(array($msg), $req_url);
    }
}

function isTrusted($trust_root)
{
    global $trusted_sites;
    return in_array($trust_root, $trusted_sites);
}

function doError($error)
{
    showError($error, '500', 'Internal error');
    exit(1);
}

function badAuth($info)
{
    doError('Unexpectedly got DO_AUTH inside of DO_AUTH');
}

function handleResponse($response, $do_auth)
{
    list ($status, $info) = $response;
    switch($status) {
    case Auth_OpenID_REMOTE_ERROR:
    case Auth_OpenID_REMOTE_OK:
        returnKV($info);
        break;
    case Auth_OpenID_REDIRECT:
        redirect($info);
        break;
    case Auth_OpenID_DO_AUTH:
        $do_auth($info);
        break;
    case Auth_OpenID_DO_ABOUT:
        aboutPage();
        break;
    case Auth_OpenID_LOCAL_ERROR:
        showError($info, '400', 'Bad request');
        break;
    default:
        $repr = var_export($status, true);
        doError("Internal error: unknown status $repr");
    }
    exit(0);
}


function loginForm($identity_url='')
{
    return sprintf(login_form_pat, $identity_url);
}

function showErrors($errors)
{
    if ($errors) {
        foreach ($errors as $error) {
            print '<div class="error">' . $error . "</div>\n";
        }
    }
}

function loginPage($errors=null, $input=null)
{
    $current_user = getLoggedInUser();
    if ($input === null) {
        $input = $current_user;
    }
    print pageHeader($current_user, 'Log In', null, true);
    showErrors($errors);
    print loginForm(htmlspecialchars($input, ENT_QUOTES));
    print pageFoot();
}

function trustPage($info)
{
    $current_user = getLoggedInUser();
    print pageHeader($current_user, 'Trust This Site');
    print '<p>' . htmlspecialchars($info->getTrustRoot()) . '</p>';
    print '<form method="post" action="trust.php">
<input type="submit" name="trust" value="Trust this site" />
<input type="submit" value="Do not trust this site" />
</form>
';
    print pageFoot();
}

function aboutPage()
{
    $current_user = getLoggedInUser();
    print pageHeader($current_user, 'OpenID Server Endpoint');
    print pageFoot();
}

define('login_form_pat',
       '<div class="login">
  <p>
    Enter your identity URL and password into this form to log in to
    this server. This server must be configured to accept your identity URL.
  </p>

  <form method="post" action="login.php">
    <table>
      <tr>
        <th><label for="openid_url">OpenID URL:</label></th>
        <td><input type="text" name="openid_url"
                   value="%s" id="openid_url" /></td>
      </tr>
      <tr>
        <th><label for="password">Password:</label></th>
        <td><input type="password" name="password" id="password" /></td>
      </tr>
      <tr>
        <td colspan="2"><input type="submit" value="Log in" /></td>
      </tr>
    </table>
  </form>
</div>
');
define('html_start',
'<html>
  <head>
    <title>%s</title>
    <link rel="stylesheet" type="text/css" href="default.css" />
  </head>
  <body>
    <h2>PHP OpenID Server</h2>
    <h1>%s</h1>
    <div class="header">%s</div>
');
define('html_end',
       '  </body>
</html>');

define('bad_user_pat',
       'You are logged in as %s and this request is for %s.');
define('no_user_pat',
       'You are not logged in and this request is for %s.');

define('logged_in_pat',
       'You are logged in as %s. <a href="logout.php">Log out</a>');
define('logged_out_pat',
       'Not logged in. <a href="login.php">Log in</a>');

?>