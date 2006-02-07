<?php

require_once "common.php";

// Set up the current session
init();

$server = getServer();
$response = $server->getOpenIDResponse();
handleResponse($response, 'doAuth');

?>