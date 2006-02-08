<?php

require_once 'config.php';
require_once 'lib/session.php';
require_once 'lib/actions.php';

init();

$action = getAction();
if (!function_exists($action)) {
    $action = 'action_default';
}

$resp = $action();

writeResponse($resp);

?>