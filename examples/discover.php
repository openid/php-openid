<?php

require_once "consumer/common.php";

require_once "Auth/OpenID/Discover.php";
require_once "Auth/Yadis/Yadis.php";

function getOpenIDIdentifier()
{
    return $_GET['openid_identifier'];
}

function escape($x)
{
    return htmlentities($x);
}


$identifier = getOpenIDIdentifier();
?>
<html>
<head>
<title>OpenID discovery</title>
</head>
<body>
  <h2>OpenID discovery tool</h2>
  <p>
    Enter an OpenID URL to begin discovery:
  </p>
  <form>
  <input type="text" name="openid_identifier" size="40" />
  <input type="submit" value="Begin" />
  </form>
<?
if ($identifier) {

    $fetcher = Auth_Yadis_Yadis::getHTTPFetcher();
    list($normalized_identifier, $endpoints) = Auth_OpenID_discover(
        $identifier, $fetcher);

?>
  <h3>Discovery Results for <?= escape($identifier) ?></h3>

  <table cellpadding="7" cellspacing="0">
    <tbody>
      <tr>
        <th>Claimed Identifier</th>
        <td><?= escape($normalized_identifier) ?></td>
      </tr>
<?
if (!$endpoints) {
?>
    <tr>
      <td colspan="2">No OpenID services discovered.</td>
    </tr>
<?
} else {
?>
    <tr>
      <td colspan="2">Discovered OpenID services:</td>
    </tr>
<?
foreach ($endpoints as $endpoint) {
?>
    <tr>
      <td colspan="2"><hr/></td>
    </tr>
    <tr>
      <th>Server URL</th>
      <td><tt><?= escape($endpoint->server_url) ?></tt></td>
    </tr>
    <tr>
      <th>Local ID</th>
      <td><tt><?= escape($endpoint->local_id) ?></tt></td>
    </tr>
    <tr>
      <td colspan="2">
        <h3>Service types:</h3>
        <ul>
<?
foreach ($endpoint->type_uris as $type_uri) {
?>
          <li><tt><?= escape($type_uri) ?></tt></li>
<?
}
?>
        </ul>
      </td>
    </tr>
<?
}
}
?>
  </tbody>
</table>
<?
}
?>
</body>
</html>