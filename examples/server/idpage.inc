<?php
if (getCurrentURL(true) != $target) {
    redirect($target);
    return;
}

$link_here = linkURL($target);
$link_there = linkURL($other);

print "<html>
  <head>
    <title>$title</title>
    <link rel='openid.server' href='$esc_server' />
  </head>
  <body>
    <h1>$title</h1>
    <p>
      This page is part of the
      <a href='$esc_server'>PHP OpenID server example</a>.
      Any requests to verify this URL ($link_here) will $type to consumers.
    </p>
    <p>
      To test this server with a URL that will $other_type, use $link_there.
    </p>
  </body>
</html>
";

?>