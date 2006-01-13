<?php

/**
 * A demonstration of the PHP OpenID Consumer.  This script assumes
 * Net/OpenID has been installed and is in your PHP include path.
 */

session_start();

require_once("Net/OpenID/Store/FileStore.php");
require_once("Net/OpenID/Consumer/Consumer.php");
require_once("Net/OpenID/OIDUtil.php");

$store_path = "/tmp/_php_consumer_test";

if (!_ensureDir($store_path)) {
    print "Could not create directory '$store_path'.  Please check the ".
        "file's permissions.";
    exit(0);
}

$store = new Net_OpenID_FileStore($store_path);
$consumer = new Net_OpenID_Consumer($store);

$action = null;

if (array_key_exists('action', $_GET)) {
    $action = $_GET['action'];
}

$self_url = $_SERVER['PHP_SELF'];

$urls = array('verify' => $self_url . "?action=verify",
              'process' => $self_url . "?action=process");

if (!array_key_exists($action, $urls)) {
    // Default behavior.
    $action = 'default_page';
}

$action();



function quoteattr($s)
{
    $s = str_replace('"', '&quot;', $s);
    return sprintf('"%s"', $s);
}

function print_header($title)
{

    $header_str = "<html>
  <head><title>%s</title></head>
  <style type=\"text/css\">
      * {
        font-family: verdana,sans-serif;
      }
      body {
        width: 50em;
        margin: 1em;
      }
      div {
        padding: .5em;
      }
      table {
        margin: none;
        padding: none;
      }
      .alert {
        border: 1px solid #e7dc2b;
        background: #fff888;
      }
      .error {
        border: 1px solid #ff0000;
        background: #ffaaaa;
      }
      #verify-form {
        border: 1px solid #777777;
        background: #dddddd;
        margin-top: 1em;
        padding-bottom: 0em;
      }
  </style>
  <body>
    <h1>%s</h1>
    <p>
      This example consumer uses the <a
      href=\"http://www.openidenabled.com/openid/libraries/php/\">PHP
      OpenID</a> library. It just verifies that the URL that you enter
      is your identity URL.
    </p>";

    print sprintf($header_str, $title, $title);
}

function print_footer()
{
    global $urls;

    $footer_str = "
    <div id=\"verify-form\">
      <form method=\"get\" action=%s>
        Identity&nbsp;URL:
        <input type=\"hidden\" name=\"action\" value=\"verify\" />
        <input type=\"text\" name=\"openid_url\" value=\"\" />
        <input type=\"submit\" value=\"Verify\" />
      </form>
    </div>
  </body>
</html>";
    print sprintf($footer_str, quoteattr($urls['verify']));
}

function default_page()
{
    render();
}

function render($message = null, $css_class = null,
                $title = "PHP OpenID Consumer Example")
{
    print_header($title);
    if ($message) {
        if (!$css_class) {
            $css_class = 'alert';
        }
        print "<div class=\"$css_class\">$message</div>";
    }
    print_footer();
}

function verify()
{
    global $consumer, $urls, $self_url,
        $Net_OpenID_HTTP_FAILURE,
        $Net_OpenID_PARSE_ERROR,
        $Net_OpenID_SUCCESS;

    if (!array_key_exists('openid_url', $_GET) ||
        !$_GET['openid_url']) {
        default_page();
        return;
    }

    $openid_url = $_GET['openid_url'];

    list($status, $info) = $consumer->beginAuth($openid_url);

    if (in_array($status, array($Net_OpenID_HTTP_FAILURE, $Net_OpenID_PARSE_ERROR))) {
        if ($status == $Net_OpenID_HTTP_FAILURE) {
            render("HTTP failure");
        } else {
            render("HTTP Parse error");
        }
    } else if ($status == $Net_OpenID_SUCCESS) {
        $_SESSION['openid_token'] = $info->token;
        $return_to = "http://".$_SERVER['HTTP_HOST'].$urls['process'];
        $redirect_url = @$consumer->constructRedirect($info, $return_to,
                                                      "http://" . $_SERVER['HTTP_HOST']);

        header("Location: ".$redirect_url);
    } else {
        render("Got unexpected status: '$status'");
    }
}

function process()
{
    global $consumer,
        $Net_OpenID_SUCCESS,
        $Net_OpenID_FAILURE;

    // retrieve the token from the environment (in this case, the URL)
    $token = $_SESSION['openid_token'];

    // Ask the library to check the response that the server sent us.
    // Status is a code indicating the response type. info is either
    // None or a string containing more information about the return
    // type.
    $data = Net_OpenID_Consumer::fixResponse($_GET);

    list($status, $info) = $consumer->completeAuth($token, $data);

    $css_class = 'error';
    $openid_url = null;

    if (($status == $Net_OpenID_FAILURE) &&
        $info) {
        // In the case of failure, if info is non-None, it is the URL
        // that we were verifying. We include it in the error message
        // to help the user figure out what happened.
        $openid_url = $info;
        $fmt = "Verification of %s failed.";
        $message = sprintf($fmt, $openid_url);
    } else if ($status == $Net_OpenID_SUCCESS) {
        // Success means that the transaction completed without
        // error. If info is None, it means that the user cancelled
        // the verification.
        $css_class = 'alert';
        if ($info) {
            // This is a successful verification attempt. If this was
            // a real application, we would do our login, comment
            // posting, etc. here.
            $openid_url = $info;
            $fmt = "You have successfully verified %s as your identity.";
            $message = sprintf($fmt, $openid_url);
        } else {
            // cancelled
            $message = 'Verification cancelled';
        }
    } else {
        // Either we don't understand the code or there is no
        // openid_url included with the error. Give a generic failure
        // message. The library should supply debug information in a
        // log.
        $message = 'Verification failed.';
    }

    render($message, $css_class);
}

?>