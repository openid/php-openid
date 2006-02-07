<?php

require_once "common.php";

// Set up the current session
init();

setLoggedInUser(null);
unset($_SESSION['request']);
redirect($server_url);

?>