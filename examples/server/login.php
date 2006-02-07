<?php

require_once 'common.php';

function processForm($fields)
{
    global $server_url;
    $errors = array();
    $openid_url = checkInput($fields, $errors);
    if ($openid_url) {
        setLoggedInUser($openid_url);
        if (isset($_SESSION['request'])) {
            $info = unserialize($_SESSION['request']);
            trustPage($info);
        } else {
            redirect($server_url);
        }
    } else {
        loginPage($errors, @$_POST['openid_url'], null, true);
    }
}

function checkInput($input, &$errors)
{
    $errors = array();
    if (!isset($input['openid_url'])) {
        $errors[] = 'Enter an OpenID URL to continue';
    }
    if (!isset($input['password'])) {
        $errors[] = 'Enter a password to continue';
    }
    if (count($errors) == 0) {
        $openid_url = $input['openid_url'];
        $password = $input['password'];
        if (!checkLogin($openid_url, $password)) {
            $errors[] = 'Password does not match identity URL';
        } else {
            return $openid_url;
        }
    }
    return false;
}

function process()
{
    $method = $_SERVER['REQUEST_METHOD'];
    switch ($method) {
    case 'GET':
        loginPage();
        break;
    case 'POST':
        processForm($_POST);
        break;
    default:
        loginPage(array('Unsupported HTTP method: $method'));
        break;
    }
}

// Set up the current session
init();

process();
?>