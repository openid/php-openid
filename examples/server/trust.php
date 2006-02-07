<?php

require_once "common.php";

init();

if (!isset($_SESSION['request'])) {
    // Should not happen
    redirect($server_url);
}

$info = unserialize($_SESSION['request']);

unset($_SESSION['request']);

if (isset($_POST['trust'])) {
    // This is a trusted site, so continue
    succeed($info);
} else {
    redirect($info->getCancelURL());
}

?>