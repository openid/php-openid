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
        $this->noauth = '_Auth_OpenID_NotAuthorized';

        $this->store = new Tests_Auth_OpenID_MemStore();
        $this->server =& new Auth_OpenID_Server($this->sv_url, &$this->store);
    }

    function test_getWithReturnToError()
    {
        $args = array(
                      'openid.mode' => 'monkeydance',
                      'openid.identity' => $this->id_url,
                      'openid.return_to' => $this->rt_url,
                      );

        list($status, $info) = $this->server->getOpenIDResponse(
            $this->noauth, 'GET', $args);

        $this->assertEquals(Auth_OpenID_REDIRECT, $status);
        list($rt_base, $query) = explode('?', $info, 2);

        $resultArgs = array();
        parse_str($query, $resultArgs);
        $resultArgs = Auth_OpenID_fixArgs($resultArgs);

        $this->assertEquals($this->rt_url, $rt_base);
        $this->assertEquals('error', $resultArgs['openid.mode']);
        if (!array_key_exists('openid.error', $resultArgs)) {
            $dump = var_export($resultArgs, true);
            $msg = sprintf("no openid.error in %s", $dump);
            $this->fail($msg);
        }
    }

    function test_getBadArgsError()
    {
        $args = array(
                      'openid.mode' => 'zebradance',
                      'openid.identity' => $this->id_url,
                      );

        list($status, $info) = $this->server->getOpenIDResponse(
            $this->noauth, 'GET', $args);

        $this->assertEquals(Auth_OpenID_LOCAL_ERROR, $status);
        $this->assertTrue($info);
    }

    function test_getNoArgsError()
    {
        list($status, $info) = $this->server->getOpenIDResponse(
            $this->noauth, 'GET', array());

        $this->assertEquals(Auth_OpenID_DO_ABOUT, $status);
    }

    function test_postError()
    {
        $args = array(
                      'openid.mode' => 'pandadance',
                      'openid.identity' => $this->id_url,
                      );

        list($status, $info) = $this->server->getOpenIDResponse(
            $this->noauth, 'POST', $args);

        $this->assertEquals(Auth_OpenID_REMOTE_ERROR, $status);
        $resultArgs = Auth_OpenID_KVForm::kvToArray($info);
        $this->assertTrue(array_key_exists('error', $resultArgs));
    }

    function assertKeyExists($key, $ary)
    {
        $this->assertTrue(array_key_exists($key, $ary),
                          "Failed to find $key in $ary");
    }

    function assertKeyAbsent($key, $ary)
    {
        $this->assertFalse(array_key_exists($key, $ary),
                           "Unexpectedly found $key in $ary");
    }

    function test_associatePlain()
    {
        list($status, $info) = $this->server->associate(array());

        $this->assertEquals(Auth_OpenID_REMOTE_OK, $status);
        $ra = Auth_OpenID_KVForm::kvToArray($info);
        $this->assertEquals('HMAC-SHA1', $ra['assoc_type']);
        $this->assertKeyAbsent('session_type', $ra);
        $this->assertKeyExists('assoc_handle', $ra);
        $this->assertKeyExists('mac_key', $ra);
        $exp = (integer)$ra['expires_in'];
        $this->assertTrue($exp > 0);
    }
}
