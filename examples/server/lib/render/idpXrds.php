<?php

require_once "lib/session.php";
require_once "lib/render.php";

define('xrds_pat', '<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS
    xmlns:xrds="xri://$xrds"
    xmlns="xri://$xrd*($v*2.0)">
  <XRD>
    <Service priority="0">
      <Type>http://specs.openid.net/auth/2.0/server</Type>
      <URI>%s</URI>
    </Service>
  </XRD>
</xrds:XRDS>
');

function idpXrds_render()
{
    $headers = array('Content-type: application/xrds+xml');

    $body = sprintf(xrds_pat, buildURL());

    return array($headers, $body);
}

?>