<?php

require_once "lib/session.php";
require_once "lib/render.php";

define('idpage_pat',
       '<html>
<head>
  <link rel="openid2.provider openid.server" href="%s"/>
</head>
<body>
  This is the identity page for users of this server.
</body>
</html>');

function idpage_render($identity)
{
    $body = sprintf(idpage_pat, buildURL());
    return array(array(), $body);
}

?>