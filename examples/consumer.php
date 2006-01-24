<?php

/**
 * A demonstration of the PHP OpenID Consumer.  This script assumes
 * Auth/OpenID has been installed and is in your PHP include path.
 */

/**
 * Require the OpenID consumer code.
 */
require_once "Auth/OpenID/Consumer/Consumer.php";

/**
 * Require the "file store" module, which we'll need to store OpenID
 * information.
 */
require_once "Auth/OpenID/Store/FileStore.php";

/**
 * This is where the example will store its OpenID information.  You
 * should change this path if you want the example store to be created
 * elsewhere.  After you're done playing with the example script,
 * you'll have to remove this directory manually.
 */
$store_path = "/tmp/_php_consumer_test";

if (!file_exists($store_path) &&
    !mkdir($store_path)) {
    print "Could not create the FileStore directory '$store_path'. ".
        " Please check the effective permissions.";
    exit(0);
}

$store = new Auth_OpenID_FileStore($store_path);

/**
 * Create a consumer object using the store object created earlier.
 */
$consumer = new Auth_OpenID_Consumer($store);

/**
 * Start the PHP session.
 */
session_start();

/**
 * Examine the CGI environment to find out what we should do.
 */
$action = null;
if (array_key_exists('action', $_GET)) {
    $action = $_GET['action'];
}

/**
 * Get this script's URL (since it's an example and may vary widely)
 * and use it later when building URLs to use in the OpenID auth
 * system.
 */
$self_url = $_SERVER['PHP_SELF'];

/**
 * These are the allowed values of the CGI 'action' variable.
 * Anything else will be ignored and will result in a default page.
 */
$urls = array('verify' => $self_url . "?action=verify",
              'process' => $self_url . "?action=process");

if (!array_key_exists($action, $urls)) {
    // Default behavior.
    $action = 'default_page';
}

/**
 * Run the approriatley-named function based on the scrubbed value of
 * $action.
 */
$action();


/**
 * Escapes double quotes in a value and returns the value wrapped in
 * double quotes for use as an HTML attribute.
 */
function quoteattr($s)
{
    $s = str_replace('"', '&quot;', $s);
    return sprintf('"%s"', $s);
}

/**
 * Prints the page header with a specified title.
 */
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

/**
 * Prints the page footer, which also includes the OpenID auth form.
 */
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

/**
 * Render a default page.
 */
function default_page()
{
    render();
}

/**
 * Use some parameters to render a page with the specified title,
 * including an optional message and CSS class to format the message
 * in case the caller wants to display a notification or error.
 */
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

/**
 * Process the OpenID auth form submission by starting the OpenID auth
 * process.
 */
function verify()
{
    global $consumer, $urls, $self_url;

    // Render a default page if we got a submission without an
    // openid_url value.
    if (!array_key_exists('openid_url', $_GET) ||
        !$_GET['openid_url']) {
        default_page();
        return;
    }

    $openid_url = $_GET['openid_url'];

    // Begin the OpenID authentication process.
    list($status, $info) = $consumer->beginAuth($openid_url);

    // Handle failure status return values.
    if (in_array($status, array(Auth_OpenID_HTTP_FAILURE, Auth_OpenID_PARSE_ERROR))) {
        if ($status == Auth_OpenID_HTTP_FAILURE) {
            render("HTTP failure");
        } else {
            render("HTTP Parse error");
        }
    } else if ($status == Auth_OpenID_SUCCESS) {
        // If we got a successful return, continue the auth by
        // redirecting the user agent to the OpenID server.  Be sure
        // to give the server a URL that will cause this script's
        // "process" function to process the server's response.
        $_SESSION['openid_token'] = $info->token;
        $return_to = "http://".$_SERVER['HTTP_HOST'].$urls['process'];
        $redirect_url = @$consumer->constructRedirect($info, $return_to,
                                                      "http://" . $_SERVER['HTTP_HOST']);

        header("Location: ".$redirect_url);
    } else {
        render("Got unexpected status: '$status'");
    }
}

/**
 * Process the response from an OpenID server.
 */
function process()
{
    global $consumer;

    // Retrieve the token from the session.
    $token = $_SESSION['openid_token'];

    // Ask the library to check the response that the server sent us.
    // Status is a code indicating the response type. info is either
    // None or a string containing more information about the return
    // type.

    // Complete the authentication process using the server's
    // response.
    list($status, $info) = $consumer->completeAuth($token, $_GET);

    $css_class = 'error';
    $openid_url = null;

    // React to the server's response status.
    if (($status == Auth_OpenID_FAILURE) &&
        $info) {
        // In the case of failure, if info is non-None, it is the URL
        // that we were verifying. We include it in the error message
        // to help the user figure out what happened.
        $openid_url = $info;
        $fmt = "Verification of %s failed.";
        $message = sprintf($fmt, $openid_url);
    } else if ($status == Auth_OpenID_SUCCESS) {
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
