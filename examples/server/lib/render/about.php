<?php

require_once "lib/session.php";
require_once "lib/render.php";

define('about_error_template',
       '<div class="error">
An error occurred when processing your request:
<br />
%s
</div>');

define('about_body',
       '<p>
  This is an <a href="http://www.openid.net/">OpenID</a> server
  endpoint. This server is built on the <a
  href="http://www.openidenabled.com/openid/libraries/php">JanRain PHP OpenID
  library</a>. Since OpenID consumer sites will need to directly contact this
  server, it must be accessible over the Internet (not behind a firewall).
</p>
<p>
  To use this server, you will have to set up a URL to use as an identifier.
  Insert the following markup into the <code>&lt;head&gt;</code> of the HTML
  document at that URL:
</p>
<pre>&lt;link rel="openid.server" href="%s" /&gt;</pre>
<p>
  Then configure this server so that you can log in with that URL. Once you
  have configured the server, and marked up your identity URL, you can verify
  that it is working by using the <a href="http://www.openidenabled.com/"
  >openidenabled.com</a>
  <a href="http://www.openidenabled.com/resources/openid-test/checkup">OpenID
  Checkup tool</a>:
  <form method="post"
        action="http://www.openidenabled.com/resources/openid-test/checkup/start">
    <label for="checkup">OpenID URL:
    </label><input id="checkup" type="text" name="openid_url" />
    <input type="submit" value="Check" />
  </form>
</p>
');

/**
 * Render the about page, potentially with an error message
 */
function about_render($error=false, $internal=true)
{
    $headers = array();
    $body = sprintf(about_body, buildURL());
    if ($error) {
        $headers[] = $internal ? http_internal_error : http_bad_request;
        $body .= sprintf(about_error_template, htmlspecialchars($error));
    }
    $current_user = getLoggedInUser();
    return page_render($body, $current_user, 'OpenID Server Endpoint');
}

?>