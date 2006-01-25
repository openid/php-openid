<?php

/**
 * Tests for Auth_OpenID_Server
 */

require_once "PHPUnit.php";
require_once "Tests/Auth/OpenID/MemStore.php";
require_once "Auth/OpenID/Server.php";

function _Auth_OpenID_NotAuthorized()
{
    return false;
}

class Tests_Auth_OpenID_Server extends PHPUnit_TestCase {
    function setUp()
    {
        $this->sv_url = 'http://id.server.url/';
        $this->id_url = 'http://foo.com/';
        $this->rt_url = 'http://return.to/rt';
        $this->tr_url = 'http://return.to/';

        $this->store = new Tests_Auth_OpenID_MemStore();
        $this->server =& new Auth_OpenID_Server($this->sv_url, &$this->store);
    }

    function test_getWithReturnTo()
    {
        $args = array(
                      'openid.mode' => 'monkeydance',
                      'openid.identity' => $this->id_url,
                      'openid.return_to' => $this->rt_url,
                      );

        list($status, $info) = $this->server->getOpenIDResponse(
            '_Auth_OpenID_NotAuthorized', 'GET', $args);

        $this->assertEquals($status, Auth_OpenID_REDIRECT);
        list($rt_base, $query) = explode('?', $info, 2);

        $resultArgs = array();
        parse_str($query, $resultArgs);
        $resultArgs = Auth_OpenID_fixArgs($resultArgs);

        $this->assertEquals($rt_base, $this->rt_url);
        $this->assertEquals($resultArgs['openid.mode'], 'error');
        if (!array_key_exists('openid.error', $resultArgs)) {
            $dump = var_export($resultArgs, true);
            $msg = sprintf("no openid.error in %s", $dump);
            $this->fail($msg);
        }
    }

    function test_getBadArgs()
    {
        $args = array(
                      'openid.mode' => 'zebradance',
                      'openid.identity' => $this->id_url,
                      );

        list($status, $info) = $this->server->getOpenIDResponse(
            '_Auth_OpenID_NotAuthorized', 'GET', $args);

        $this->assertEquals($status, Auth_OpenID_LOCAL_ERROR);
        $this->assertTrue($info);
    }

    function test_getNoArgs()
    {
        list($status, $info) = $this->server->getOpenIDResponse(
            '_Auth_OpenID_NotAuthorized', 'GET', array());

        $this->assertEquals($status, Auth_OpenID_DO_ABOUT);
    }
}
