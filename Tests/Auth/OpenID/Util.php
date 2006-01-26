<?php

/**
 * Utilites for test functions
 */

function Tests_Auth_OpenID_readlines($name)
{
    $path = dirname(realpath(__FILE__));
    $sep = DIRECTORY_SEPARATOR;
    $data_file_name = $path . $sep . 'data' . $sep . $name;
    $lines = file($data_file_name);
    if ($lines === false) {
        trigger_error("Failed to open data file: $dh_test_data_file",
                      E_USER_ERROR);
    }
    return $lines;
}
