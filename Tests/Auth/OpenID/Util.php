<?php

/**
 * Utilites for test functions
 */

function Tests_Auth_OpenID_readlines($name)
{
    $path = dirname(realpath(__FILE__));
    $data_file_name = $path . DIRECTORY_SEPARATOR . $name;
    $lines = file($data_file_name);
    if ($lines === false) {
        trigger_error("Failed to open data file: $dh_test_data_file",
                      E_USER_ERROR);
    }
    return $lines;
}
