<?php $title = 'PHP OpenID Server Example'; ?>
<html>
  <head>
    <title><?php print $title; ?></title>
  </head>
  <body>
    <h1><?php print $title; ?></h1>
    <p>
      This is an example PHP OpenID server. It is using the <a
          href="http://www.openidenabled.com/openid/libraries/php">JanRain
      PHP OpenID library</a>. This server will approve any request
      for the URL <?php
$esc_id = htmlspecialchars($success_identity, ENT_QUOTES);
print "<a href='$esc_id'>$esc_id</a>";
      ?> and reject requests for any other URL.
    </p>
  </body>
</html>
