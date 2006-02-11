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

    function _parseRedirResp($ret)
    {
        list($status, $redir) = $ret;
        if ($status != Auth_OpenID_REDIRECT) {
            $this->fail("Bad status: $status");
            return false;
        }

        list($base, $query_str) = explode('?', $redir, 2);

        $query = array();
        parse_str($query_str, $query);
        $query = Auth_OpenID_fixArgs($query);
        return array($base, $query);
    }

    function test_getWithReturnToError()
    {
        $args = array(
                      'openid.mode' => 'monkeydance',
                      'openid.identity' => $this->id_url,
                      'openid.return_to' => $this->rt_url,
                      );

        $ret = $this->server->getOpenIDResponse($this->noauth, 'GET', $args);

        list($rt_base, $resultArgs) = $this->_parseRedirResp($ret);

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
        $resultArgs = Auth_OpenID_KVForm::toArray($info);
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
        $ra = Auth_OpenID_KVForm::toArray($info);
        $this->assertEquals('HMAC-SHA1', $ra['assoc_type']);
        $this->assertKeyAbsent('session_type', $ra);
        $this->assertKeyExists('assoc_handle', $ra);
        $this->assertKeyExists('mac_key', $ra);
        $exp = (integer)$ra['expires_in'];
        $this->assertTrue($exp > 0);
    }

    function test_associateDHdefaults()
    {
        if (defined('Auth_OpenID_NO_MATH_SUPPORT')) {
            return;
        }

        $dh = new Auth_OpenID_DiffieHellman();
        $args = $dh->getAssocArgs();
        list($status, $info) = $this->server->associate($args);
        $this->assertEquals(Auth_OpenID_REMOTE_OK, $status);

        $ra = Auth_OpenID_KVForm::toArray($info);
        $this->assertEquals('HMAC-SHA1', $ra['assoc_type']);
        $this->assertEquals('DH-SHA1', $ra['session_type']);
        $this->assertKeyExists('assoc_handle', $ra);
        $this->assertKeyExists('dh_server_public', $ra);
        $this->assertKeyAbsent('mac_key', $ra);
        $exp = (integer)$ra['expires_in'];
        $this->assertTrue($exp > 0);
        $secret = $dh->consumerFinish($ra);
        $this->assertEquals('string', gettype($secret));
        $this->assertTrue(strlen($secret) > 0);
    }

    function test_associateDHnoKey()
    {
        $args = array('openid.session_type' => 'DH-SHA1');
        list($status, $info) = $this->server->associate($args);
        if (defined('Auth_OpenID_NO_MATH_SUPPORT')) {
            $this->assertEquals(Auth_OpenID_REMOTE_OK, $status);
            $ra = Auth_OpenID_KVForm::toArray($info);
            $this->assertEquals('HMAC-SHA1', $ra['assoc_type']);
            $this->assertKeyExists('assoc_handle', $ra);
            $this->assertKeyExists('mac_key', $ra);
            $exp = (integer)$ra['expires_in'];
            $this->assertTrue($exp > 0);
        } else {
            $this->assertEquals(Auth_OpenID_REMOTE_ERROR, $status);
            $ra = Auth_OpenID_KVForm::toArray($info);
            $this->assertKeyExists('error', $ra);
        }
    }

    function _buildURL($base, $query)
    {
        $result = $base;
        $div = '?';
        foreach ($query as $k => $v) {
            $result .= sprintf("%s%s=%s", $div, urlencode($k), urlencode($v));
            $div = '&';
        }
        return $result;
    }

    function _startAuth($mode, $authorized)
    {
        $args = array(
                      'openid.mode' => $mode,
                      'openid.identity' => $this->id_url,
                      'openid.return_to' => $this->rt_url,
                      );
        $ainfo = new Auth_OpenID_ServerRequest($this->sv_url, $args);
        return $this->server->getAuthResponse(&$ainfo, $authorized);
    }

    function test_checkIdImmediateFailure()
    {
        $ret = $this->_startAuth('checkid_immediate', false);
        list($base, $query) = $this->_parseRedirResp($ret);

        $setup_args = array('openid.identity' => $this->id_url,
                            'openid.mode' => 'checkid_setup',
                            'openid.return_to' => $this->rt_url,
                            );
        $setup_url = $this->_buildURL($this->sv_url, $setup_args);

        $eargs = array('openid.mode' => 'id_res',
                       'openid.user_setup_url' => $setup_url);

        $this->assertEquals($eargs, $query);
        $this->assertEquals($this->rt_url, $base);
    }

    function _checkIDGood($mode)
    {
        $ret = $this->_startAuth($mode, true);
        list($base, $query) = $this->_parseRedirResp($ret);
        $this->assertEquals($base, $this->rt_url);
        $this->assertEquals($query['openid.mode'], 'id_res');
        $this->assertEquals($query['openid.identity'], $this->id_url);
        $this->assertEquals($query['openid.return_to'], $this->rt_url);
        $this->assertEquals('mode,identity,return_to', $query['openid.signed']);

        $assoc = $this->store->getAssociation($this->server->_dumb_key,
                                              $query['openid.assoc_handle']);
        $this->assertNotNull($assoc);
        $expected = $assoc->sign(array('mode' => 'id_res',
                                       'identity' => $this->id_url,
                                       'return_to' => $this->rt_url,
                                       ));
        $expected64 = base64_encode($expected);
        $this->assertEquals($expected64, $query['openid.sig']);
    }

    function test_checkIdImmediate()
    {
        $this->_checkIDGood('checkid_immediate');
    }

    function test_checkIdSetup()
    {
        $this->_checkIDGood('checkid_setup');
    }

    function test_checkIdSetupNeedAuth()
    {
        $args = array(
                      'openid.mode' => 'checkid_setup',
                      'openid.identity' => $this->id_url,
                      'openid.return_to' => $this->rt_url,
                      'openid.trust_root' => $this->tr_url,
                      );

        $ainfo = new Auth_OpenID_ServerRequest($this->sv_url, $args);
        list($status, $info) = $this->server->getAuthResponse(&$ainfo, false);
        $this->assertEquals(Auth_OpenID_DO_AUTH, $status);
        $this->assertEquals($this->tr_url, $info->getTrustRoot());
        $this->assertEquals($this->id_url, $info->getIdentityURL());
    }

    function test_checkIdSetupCancel()
    {
        list($status, $info) = $this->_startAuth('checkid_setup', false);
        $this->assertEquals(Auth_OpenID_DO_AUTH, $status);
        list($base, $query) = $this->_parseRedirResp($info->cancel());
        $this->assertEquals($this->rt_url, $base);
        $this->assertEquals('cancel', $query['openid.mode']);
    }

    function _setupCheckAuth()
    {
        $ret = $this->_startAuth('checkid_immediate', true);
        list($base, $query) = $this->_parseRedirResp($ret);
        $this->assertEquals($base, $this->rt_url);
        $query['openid.mode'] = 'check_authentication';
        return $query;
    }

    function test_checkAuthentication()
    {
        $args = $this->_setupCheckAuth();
        list($status, $info) = $this->server->checkAuthentication($args);
        $this->assertEquals(Auth_OpenID_REMOTE_OK, $status);
        $this->assertEquals("is_valid:true\n", $info);
    }

    function test_checkAuthenticationFailSig()
    {
        $args = $this->_setupCheckAuth();
        $args['openid.sig'] = str_rot13($args['openid.sig']);
        list($status, $info) = $this->server->checkAuthentication($args);
        $this->assertEquals(Auth_OpenID_REMOTE_OK, $status);
        $this->assertEquals("is_valid:false\n", $info);
    }

    function test_checkAuthenticationFailHandle()
    {
        $args = $this->_setupCheckAuth();
        $args['openid.assoc_handle'] = 'a bad handle';
        list($status, $info) = $this->server->checkAuthentication($args);
        $this->assertEquals(Auth_OpenID_REMOTE_OK, $status);
        $this->assertEquals("is_valid:false\n", $info);
    }
}
