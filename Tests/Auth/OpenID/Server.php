<?php

/**
 * Tests for Auth_OpenID_Server
 */

require_once "PHPUnit.php";
require_once "Tests/Auth/OpenID/MemStore.php";
require_once "Auth/OpenID.php";
require_once "Auth/OpenID/DiffieHellman.php";
require_once "Auth/OpenID/Server.php";

function altModulus()
{
    $lib =& Auth_OpenID_getMathLib();
    static $num = null;

    if (!$num) {
        $num = $lib->init("1423261515703355186607439952816216983770".
                          "5735494988446894302176757360889904836136".
                          "0422513557553514790045512299468953431585".
                          "3008125488594198571710943663581589034331".
                          "6791551733211386105974742540867014420109".
                          "9811846875730766487278261498262568348338".
                          "4764372005569983660877797099908075182915".
                          "81860338635288400119293970087"
                          );
    }

    return $num;
}

$ALT_GEN = 5;

function arrayToString($arr)
{
    $s = "Array(";

    $parts = array();
    foreach ($arr as $k => $v) {
        if (is_array($v)) {
            $v = arrayToString($v);
        }
        $parts[] = sprintf("%s => %s", $k, $v);
    }

    $s .= implode(", ", $parts);
    $s .= ")";

    return $s;
}

function _Auth_OpenID_NotAuthorized()
{
    return false;
}

class Tests_Auth_OpenID_Test_ServerError extends PHPUnit_TestCase {
    function test_browserWithReturnTo()
    {
        $return_to = "http://rp.unittest/consumer";
        // will be a ProtocolError raised by Decode or CheckIDRequest.answer
        $args = array(
            'openid.mode' => 'monkeydance',
            'openid.identity' => 'http://wagu.unittest/',
            'openid.return_to' => $return_to);
        $e = new Auth_OpenID_ServerError($args, "plucky");
        $this->assertTrue($e->hasReturnTo());
        $expected_args = array(
            'openid.mode' => 'error',
            'openid.error' => 'plucky');

        $encoded = $e->encodeToURL();
        if (_isError($encoded)) {
            $this->fail($encoded->toString());
            return;
        }

        list($rt_base, $_result_args) = explode("?", $e->encodeToURL(), 2);
        $result_args = array();
        parse_str($_result_args, $result_args);
        $result_args = Auth_OpenID::fixArgs($result_args);

        $this->assertEquals($result_args, $expected_args);
    }

    function test_noReturnTo()
    {
        // will be a ProtocolError raised by Decode or CheckIDRequest.answer
        $args = array(
            'openid.mode' => 'zebradance',
            'openid.identity' => 'http://wagu.unittest/');

        $e = new Auth_OpenID_ServerError($args, "waffles");
        $this->assertFalse($e->hasReturnTo());
        $expected = "error:waffles\nmode:error\n";
        $this->assertEquals($e->encodeToKVForm(), $expected);
    }
}

class Tests_Auth_OpenID_Test_Decode extends PHPUnit_TestCase {
    function setUp()
    {
        $this->id_url = "http://decoder.am.unittest/";
        $this->rt_url = "http://rp.unittest/foobot/?qux=zam";
        $this->tr_url = "http://rp.unittest/";
        $this->assoc_handle = "{assoc}{handle}";
        $this->decoder = new Auth_OpenID_Decoder();
    }

    function test_none()
    {
        $args = array();
        $r = $this->decoder->decode($args);
        $this->assertEquals($r, null);
    }

    function test_irrelevant()
    {
        $args = array(
            'pony' => 'spotted',
            'sreg.mutant_power' => 'decaffinator');

        $r = $this->decoder->decode($args);

        $this->assertTrue($r === null);
    }

    function test_bad()
    {
        $args = array(
            'openid.mode' => 'twos-compliment',
            'openid.pants' => 'zippered');

        // Be sure that decoding the args returns an error.
        $result = $this->decoder->decode($args);

        $this->assertTrue(_isError($result));
    }

    function test_checkidImmediate()
    {
        $args = array(
            'openid.mode' => 'checkid_immediate',
            'openid.identity' => $this->id_url,
            'openid.assoc_handle' => $this->assoc_handle,
            'openid.return_to' => $this->rt_url,
            'openid.trust_root' => $this->tr_url,
            # should be ignored
            'openid.some.extension' => 'junk');

        $r = $this->decoder->decode($args);
        $this->assertTrue(is_a($r, 'Auth_OpenID_CheckIDRequest'));
        $this->assertEquals($r->mode, "checkid_immediate");
        $this->assertEquals($r->immediate, true);
        $this->assertEquals($r->identity, $this->id_url);
        $this->assertEquals($r->trust_root, $this->tr_url);
        $this->assertEquals($r->return_to, $this->rt_url);
        $this->assertEquals($r->assoc_handle, $this->assoc_handle);
    }

    function test_checkidSetup()
    {
        $args = array(
            'openid.mode' => 'checkid_setup',
            'openid.identity' => $this->id_url,
            'openid.assoc_handle' => $this->assoc_handle,
            'openid.return_to' => $this->rt_url,
            'openid.trust_root' => $this->tr_url);

        $r = $this->decoder->decode($args);
        $this->assertTrue(is_a($r, 'Auth_OpenID_CheckIDRequest'));
        $this->assertEquals($r->mode, "checkid_setup");
        $this->assertEquals($r->immediate, false);
        $this->assertEquals($r->identity, $this->id_url);
        $this->assertEquals($r->trust_root, $this->tr_url);
        $this->assertEquals($r->return_to, $this->rt_url);
    }

    function test_checkidSetupNoIdentity()
    {
        $args = array(
            'openid.mode' => 'checkid_setup',
            'openid.assoc_handle' => $this->assoc_handle,
            'openid.return_to' => $this->rt_url,
            'openid.trust_root' => $this->tr_url);

        $result = $this->decoder->decode($args);
        if (_isError($result)) {
            $this->assertTrue($result->query);
        } else {
            $this->fail(sprintf("Expected Auth_OpenID_Error, instead " .
                                "returned with %s", gettype($result)));
        }
    }

    function test_checkidSetupNoReturn()
    {
        $args = array(
            'openid.mode' => 'checkid_setup',
            'openid.identity' => $this->id_url,
            'openid.assoc_handle' => $this->assoc_handle,
            'openid.trust_root' => $this->tr_url);

        $result = $this->decoder->decode($args);
        if (!_isError($result)) {
            $this->fail("Expected Auth_OpenID_Error");
        }
    }

    function test_checkidSetupBadReturn()
    {
        $args = array(
            'openid.mode' => 'checkid_setup',
            'openid.identity' => $this->id_url,
            'openid.assoc_handle' => $this->assoc_handle,
            'openid.return_to' => 'not a url');

        $result = $this->decoder->decode($args);;
        if (_isError($result)) {
            $this->assertTrue($result->query);
        } else {
            $this->fail(sprintf("Expected ProtocolError, instead " .
                                "returned with %s", gettype($result)));
        }
    }

    function test_checkAuth()
    {
        $args = array(
            'openid.mode' => 'check_authentication',
            'openid.assoc_handle' => '{dumb}{handle}',
            'openid.sig' => 'sigblob',
            'openid.signed' => 'foo,bar,mode',
            'openid.foo' => 'signedval1',
            'openid.bar' => 'signedval2',
            'openid.baz' => 'unsigned');

        $r = $this->decoder->decode($args);
        $this->assertTrue(is_a($r, 'Auth_OpenID_CheckAuthRequest'));
        $this->assertEquals($r->mode, 'check_authentication');
        $this->assertEquals($r->sig, 'sigblob');
        $this->assertEquals($r->signed, array(
            array('foo', 'signedval1'),
            array('bar', 'signedval2'),
            array('mode', 'id_res')));
    }

    function test_checkAuthMissingSignedField()
    {
        $args = array(
            'openid.mode' => 'check_authentication',
            'openid.assoc_handle' => '{dumb}{handle}',
            'openid.sig' => 'sigblob',
            'openid.signed' => 'foo,bar,mode',
            'openid.foo' => 'signedval1',
            'openid.baz' => 'unsigned');

        $r = $this->decoder->decode($args);
        $this->assertTrue(is_a($r, 'Auth_OpenID_ServerError'));
    }

    function test_checkAuthMissingSignature()
    {
        $args = array(
            'openid.mode' => 'check_authentication',
            'openid.assoc_handle' => '{dumb}{handle}',
            'openid.signed' => 'foo,bar,mode',
            'openid.foo' => 'signedval1',
            'openid.bar' => 'signedval2',
            'openid.baz' => 'unsigned');

        $r = $this->decoder->decode($args);
        $this->assertTrue(is_a($r, 'Auth_OpenID_ServerError'));
    }

    function test_checkAuthAndInvalidate()
    {
        $args = array(
            'openid.mode' => 'check_authentication',
            'openid.assoc_handle' => '{dumb}{handle}',
            'openid.invalidate_handle' => '[[SMART_handle]]',
            'openid.sig' => 'sigblob',
            'openid.signed' => 'foo,bar,mode',
            'openid.foo' => 'signedval1',
            'openid.bar' => 'signedval2',
            'openid.baz' => 'unsigned');

        $r = $this->decoder->decode($args);
        $this->assertTrue(is_a($r, 'Auth_OpenID_CheckAuthRequest'));
        $this->assertEquals($r->invalidate_handle, '[[SMART_handle]]');
    }

    function test_associateDH()
    {
        if (!defined('Auth_OpenID_NO_MATH_SUPPORT')) {
            $args = array(
                          'openid.mode' => 'associate',
                          'openid.session_type' => 'DH-SHA1',
                          'openid.dh_consumer_public' => "Rzup9265tw==");
            
            $r = $this->decoder->decode($args);
            $this->assertTrue(is_a($r, 'Auth_OpenID_AssociateRequest'));
            $this->assertEquals($r->mode, "associate");
            $this->assertEquals($r->session->session_type, "DH-SHA1");
            $this->assertEquals($r->assoc_type, "HMAC-SHA1");
            $this->assertTrue($r->session->consumer_pubkey);
        }
    }

    function test_associateDHMissingKey()
    {
        $args = array(
            'openid.mode' => 'associate',
            'openid.session_type' => 'DH-SHA1');

        // Using DH-SHA1 without supplying dh_consumer_public is an error.
        $result = $this->decoder->decode($args);
        if (!_isError($result)) {
            $this->fail(sprintf("Expected Auth_OpenID_ServerError, got %s",
                                gettype($result)));
        }
    }

    /**
     * XXX: Cannot produce a value to break base64_decode
    function test_associateDHpubKeyNotB64()
    {
        $args = array(
            'openid.mode' => 'associate',
            'openid.session_type' => 'DH-SHA1',
            'openid.dh_consumer_public' => "donkeydonkeydonkey");

        $r = $this->decoder->decode($args);
        $this->assertTrue(is_a($r, 'Auth_OpenID_ServerError'));
    }
    */

    function test_associateDHModGen()
    {
        global $ALT_GEN;

        // test dh with non-default but valid values for dh_modulus
        // and dh_gen
        $lib =& Auth_OpenID_getMathLib();

        $args = array(
            'openid.mode' => 'associate',
            'openid.session_type' => 'DH-SHA1',
            'openid.dh_consumer_public' => "Rzup9265tw==",
            'openid.dh_modulus' => $lib->longToBase64(altModulus()),
            'openid.dh_gen' => $lib->longToBase64($ALT_GEN));

        $r = $this->decoder->decode($args);
        $this->assertTrue(is_a($r, 'Auth_OpenID_AssociateRequest'));
        $this->assertEquals($r->mode, "associate");
        $this->assertEquals($r->session->session_type, "DH-SHA1");
        $this->assertEquals($r->assoc_type, "HMAC-SHA1");
        $this->assertTrue($lib->cmp($r->session->dh->mod, altModulus()) === 0);
        $this->assertTrue($lib->cmp($r->session->dh->gen, $ALT_GEN) === 0);
        $this->assertTrue($r->session->consumer_pubkey);
    }

    /**
     * XXX: Can't test invalid base64 values for mod and gen because
     * PHP's base64 decoder is much too forgiving or just plain
     * broken.
    function test_associateDHCorruptModGen()
    {
        // test dh with non-default but valid values for dh_modulus
        // and dh_gen
        $args = array(
            'openid.mode' => 'associate',
            'openid.session_type' => 'DH-SHA1',
            'openid.dh_consumer_public' => "Rzup9265tw==",
            'openid.dh_modulus' => 'pizza',
            'openid.dh_gen' => 'gnocchi');

        $r = $this->decoder->decode($args);
        print_r($r);

        $this->assertTrue(is_a($r, 'Auth_OpenID_ServerError'));
    }
    */

    function test_associateDHMissingModGen()
    {
        // test dh with non-default but valid values for dh_modulus
        // and dh_gen
        $args = array(
            'openid.mode' => 'associate',
            'openid.session_type' => 'DH-SHA1',
            'openid.dh_consumer_public' => "Rzup9265tw==",
            'openid.dh_modulus' => 'pizza');

        $r = $this->decoder->decode($args);
        $this->assertTrue(is_a($r, 'Auth_OpenID_ServerError'));
    }

    function test_associateWeirdSession()
    {
        $args = array(
            'openid.mode' => 'associate',
            'openid.session_type' => 'FLCL6',
            'openid.dh_consumer_public' => "YQ==\n");

        $r = $this->decoder->decode($args);
        $this->assertTrue(is_a($r, 'Auth_OpenID_ServerError'));
    }

    function test_associatePlain()
    {
        $args = array('openid.mode' => 'associate');

        $r = $this->decoder->decode($args);
        $this->assertTrue(is_a($r, 'Auth_OpenID_AssociateRequest'));
        $this->assertEquals($r->mode, "associate");
        $this->assertEquals($r->session->session_type, "plaintext");
        $this->assertEquals($r->assoc_type, "HMAC-SHA1");
    }

    function test_nomode()
    {
        $args = array(
            'openid.session_type' => 'DH-SHA1',
            'openid.dh_consumer_public' => "my public keeey");

        $result = $this->decoder->decode($args);
        if (!_isError($result)) {
            $this->fail(sprintf("Expected Auth_OpenID_Error",
                                gettype($result)));
        }
    }
}

class Tests_Auth_OpenID_Test_Encode extends PHPUnit_TestCase {
    function setUp()
    {
        $this->encoder = new Auth_OpenID_Encoder();
        $this->encode = $this->encoder;
    }

    function test_id_res()
    {
        $request = new Auth_OpenID_CheckIDRequest(
            'http://bombom.unittest/',
            'http://burr.unittest/',
            'http://burr.unittest/999',
            false);

        $response = new Auth_OpenID_CheckIDResponse($request);
        $response->fields = array(
            'mode' => 'id_res',
            'identity' => $request->identity,
            'return_to' => $request->return_to);

        $webresponse = $this->encoder->encode($response);
        $this->assertEquals($webresponse->code, AUTH_OPENID_HTTP_REDIRECT);
        $this->assertTrue(array_key_exists('location',
                                           $webresponse->headers));

        $location = $webresponse->headers['location'];
        $this->assertTrue(strpos($location, $request->return_to) === 0);
        //                        "%s does not start with %s" % ($location,
        //                                             $request->return_to));

        $parsed = parse_url($location);
        $query = array();
        parse_str($parsed['query'], $query);
        $query = Auth_OpenID::fixArgs($query);

        $expected = array();

        foreach ($response->fields as $k => $v) {
            $expected['openid.' . $k] = $v;
        }

        $this->assertEquals($query, $expected);
    }

    function test_cancel()
    {
        $request = new Auth_OpenID_CheckIDRequest(
            'http://bombom.unittest/',
            'http://burr.unittest/',
            'http://burr.unittest/999',
            false);

        $response = new Auth_OpenID_CheckIDResponse($request);
        $response->fields = array('mode' => 'cancel');

        $webresponse = $this->encoder->encode($response);
        $this->assertEquals($webresponse->code, AUTH_OPENID_HTTP_REDIRECT);
        $this->assertTrue(array_key_exists('location', $webresponse->headers));
    }

    function test_assocReply()
    {
        if (!defined('Auth_OpenID_NO_MATH_SUPPORT')) {
            $request = Auth_OpenID_AssociateRequest::fromQuery(array());
            $response = new Auth_OpenID_ServerResponse($request);
            $response->fields = array('assoc_handle' => "every-zig");
            $webresponse = $this->encoder->encode($response);
            $body = "assoc_handle:every-zig\n";
            $this->assertEquals($webresponse->code, AUTH_OPENID_HTTP_OK);
            $this->assertEquals($webresponse->headers, array());
            $this->assertEquals($webresponse->body, $body);
        }
    }

    function test_checkauthReply()
    {
        $request = new Auth_OpenID_CheckAuthRequest('a_sock_monkey',
                                                    'siggggg',
                                                    array());
        $response = new Auth_OpenID_ServerResponse($request);
        $response->fields = array(
            'is_valid' => 'true',
            'invalidate_handle' => 'xXxX:xXXx');

        $body = "invalidate_handle:xXxX:xXXx\nis_valid:true\n";
        $webresponse = $this->encoder->encode($response);
        $this->assertEquals($webresponse->code, AUTH_OPENID_HTTP_OK);
        $this->assertEquals($webresponse->headers, array());
        $this->assertEquals($webresponse->body, $body);
    }

    function test_unencodableError()
    {
        $args = array('openid.identity' => 'http://limu.unittest/');

        $e = new Auth_OpenID_ServerError($args, "wet paint");

        $result = $this->encoder->encode($e);
        if (!_isError($result, 'Auth_OpenID_EncodingError')) {
            $this->fail(sprintf("Expected Auth_OpenID_ServerError, got %s",
                                gettype($result)));
        }
    }

    function test_encodableError()
    {
        $args = array(
            'openid.mode' => 'associate',
            'openid.identity' => 'http://limu.unittest/');

        $body="error:snoot\nmode:error\n";
        $err = new Auth_OpenID_ServerError($args, "snoot");
        $webresponse = $this->encoder->encode($err);
        $this->assertEquals($webresponse->code, AUTH_OPENID_HTTP_ERROR);
        $this->assertEquals($webresponse->headers, array());
        $this->assertEquals($webresponse->body, $body);
    }
}

class Tests_Auth_OpenID_SigningEncode extends PHPUnit_TestCase {
    function setUp()
    {
        // Use filestore here instead of memstore
        $this->store = new Tests_Auth_OpenID_MemStore();

        $this->request = new Auth_OpenID_CheckIDRequest(
            'http://bombom.unittest/',
            'http://burr.unittest/',
            'http://burr.unittest/999',
            false);

        $this->response = new Auth_OpenID_CheckIDResponse($this->request);
        $this->response->fields = array(
            'mode' => 'id_res',
            'identity' => $this->request->identity,
            'return_to' => $this->request->return_to);

        $this->signatory = new Auth_OpenID_Signatory($this->store);
        $this->dumb_key = $this->signatory->dumb_key;
        $this->normal_key = $this->signatory->normal_key;

        $this->encoder = new Auth_OpenID_SigningEncoder($this->signatory);
    }

    function test_idres()
    {
        $assoc_handle = '{bicycle}{shed}';
        $assoc = Auth_OpenID_Association::fromExpiresIn(60, $assoc_handle,
                                                        'sekrit', 'HMAC-SHA1');
        $this->store->storeAssociation($this->normal_key, $assoc);
        $this->request->assoc_handle = $assoc_handle;
        $webresponse = $this->encoder->encode($this->response);
        $this->assertEquals($webresponse->code, AUTH_OPENID_HTTP_REDIRECT);
        $this->assertTrue(array_key_exists('location',
                                           $webresponse->headers));

        $location = $webresponse->headers['location'];
        $parsed = parse_url($location);
        $query = array();
        parse_str($parsed['query'], $query);
        $query = Auth_OpenID::fixArgs($query);

        $this->assertTrue(array_key_exists('openid.sig', $query));
        $this->assertTrue(array_key_exists('openid.assoc_handle', $query));
        $this->assertTrue(array_key_exists('openid.signed', $query));
    }

    function test_idresDumb()
    {
        $webresponse = $this->encoder->encode($this->response);
        $this->assertEquals($webresponse->code, AUTH_OPENID_HTTP_REDIRECT);
        $this->assertTrue(array_key_exists('location', $webresponse->headers));

        $location = $webresponse->headers['location'];
        $parsed = parse_url($location);
        $query = array();
        parse_str($parsed['query'], $query);
        $query = Auth_OpenID::fixArgs($query);
        $this->assertTrue(array_key_exists('openid.sig', $query));
        $this->assertTrue(array_key_exists('openid.assoc_handle', $query));
        $this->assertTrue(array_key_exists('openid.signed', $query));
    }

    function test_forgotStore()
    {
        $this->encoder->signatory = null;
        $result = $this->encoder->encode($this->response);
        if (!is_a($result, 'Auth_OpenID_ServerError')) {
            $this->fail(sprintf("Expected Auth_OpenID_ServerError, got %s",
                                gettype($result)));
        }
    }

    function test_cancel()
    {
        $request = new Auth_OpenID_CheckIDRequest(
            'http://bombom.unittest/',
            'http://burr.unittest/',
            'http://burr.unittest/999',
            false);

        $response = new Auth_OpenID_CheckIDResponse($request, 'cancel');
        $webresponse = $this->encoder->encode($response);
        $this->assertEquals($webresponse->code, AUTH_OPENID_HTTP_REDIRECT);
        $this->assertTrue(array_key_exists('location', $webresponse->headers));
        $location = $webresponse->headers['location'];
        $parsed = parse_url($location);
        $query = array();
        parse_str($parsed['query'], $query);
        $query = Auth_OpenID::fixArgs($query);
        $this->assertFalse(array_key_exists('openid.sig', $query));
    }

    function test_assocReply()
    {
        if (!defined('Auth_OpenID_NO_MATH_SUPPORT')) {
            $request = Auth_OpenID_AssociateRequest::fromQuery(array());
            $response = new Auth_OpenID_ServerResponse($request);
            $response->fields = array('assoc_handle' => "every-zig");
            $webresponse = $this->encoder->encode($response);
            $body = "assoc_handle:every-zig\n";

            $this->assertEquals($webresponse->code, AUTH_OPENID_HTTP_OK);
            $this->assertEquals($webresponse->headers, array());
            $this->assertEquals($webresponse->body, $body);
        }
    }

    function test_alreadySigned()
    {
        $this->response->fields['sig'] = 'priorSig==';
        $result = $this->encoder->encode($this->response);
        if (!is_a($result, 'Auth_OpenID_AlreadySigned')) {
            $this->fail(sprintf("Expected Auth_OpenID_AlreadySigned " .
                                "instance, got %s", gettype($result)));
        }
    }
}

class Tests_Auth_OpenID_CheckID extends PHPUnit_TestCase {
    function setUp()
    {
        $this->request = new Auth_OpenID_CheckIDRequest(
            'http://bambam.unittest/',
            'http://bar.unittest/999',
            'http://bar.unittest/',
            false);
    }

    function test_trustRootInvalid()
    {
        $this->request->trust_root = "http://foo.unittest/17";
        $this->request->return_to = "http://foo.unittest/39";
        $this->assertFalse($this->request->trustRootValid());
    }

    function test_trustRootValid()
    {
        $this->request->trust_root = "http://foo.unittest/";
        $this->request->return_to = "http://foo.unittest/39";
        $this->assertTrue($this->request->trustRootValid());
    }

    function test_answerToInvalidRoot()
    {
        $this->request->trust_root = "http://foo.unittest/17";
        $this->request->return_to = "http://foo.unittest/39";
        $result = $this->request->answer(true);
        if (!is_a($result, 'Auth_OpenID_UntrustedReturnURL')) {
            $this->fail(sprintf("Expected Auth_OpenID_UntrustedReturnURL, " .
                                "got %s", gettype($result)));
        }
        $this->assertTrue($this->request->answer(false));
    }

    function test_answerAllow()
    {
        $answer = $this->request->answer(true);

        if (_isError($answer)) {
            $this->fail($answer->toString());
            return;
        }

        $this->assertEquals($answer->request, $this->request);
        $this->assertEquals($answer->fields, array(
            'mode' => 'id_res',
            'identity' => $this->request->identity,
            'return_to' => $this->request->return_to));

        $this->assertEquals($answer->signed,
                            array("mode", "identity", "return_to"));
    }

    function test_answerAllowNoTrustRoot()
    {
        $this->request->trust_root = null;
        $answer = $this->request->answer(true);
        $this->assertEquals($answer->request, $this->request);
        $this->assertEquals($answer->fields, array(
            'mode' => 'id_res',
            'identity' => $this->request->identity,
            'return_to' => $this->request->return_to));

        $this->assertEquals($answer->signed,
                            array("mode", "identity", "return_to"));
    }

    function test_answerImmediateDeny()
    {
        $this->request->mode = 'checkid_immediate';
        $this->request->immediate = true;
        $server_url = "http://setup-url.unittest/";
        $answer = $this->request->answer(false, $server_url);
        $this->assertEquals($answer->request, $this->request);
        $this->assertEquals(count($answer->fields), 2);
        $this->assertEquals(Auth_OpenID::arrayGet($answer->fields, 'mode'),
                            'id_res');
        $this->assertTrue(strpos(Auth_OpenID::arrayGet($answer->fields,
                                                       'user_setup_url'),
                                 $server_url) == 0);

        $this->assertEquals($answer->signed, array());
    }

    function test_answerSetupDeny()
    {
        $answer = $this->request->answer(false);
        $this->assertEquals($answer->fields, array('mode' => 'cancel'));
        $this->assertEquals($answer->signed, array());
    }

    function test_getCancelURL()
    {
        $url = $this->request->getCancelURL();
        $expected = $this->request->return_to . '?openid.mode=cancel';
        $this->assertEquals($url, $expected);
    }

    function test_getCancelURLimmed()
    {
        $this->request->mode = 'checkid_immediate';
        $this->request->immediate = true;
        $result = $this->request->getCancelURL();
        if (!is_a($result, 'Auth_OpenID_ServerError')) {
            $this->fail(sprintf("Expected Auth_OpenID_ServerError, got %s",
                                gettype($result)));
        }
    }
}

class Tests_Auth_OpenID_CheckIDExtension extends PHPUnit_TestCase {

    function setUp()
    {
        $this->request = new Auth_OpenID_CheckIDRequest(
            'http://bambam.unittest/',
            'http://bar.unittest/',
            'http://bar.unittest/999',
            false);

        $this->response = new Auth_OpenID_CheckIDResponse($this->request);
        $this->response->fields['blue'] = 'star';
    }

    function test_addField()
    {
        $namespace = 'mj12';
        $this->response->addField($namespace, 'bright', 'potato');
        $this->assertEquals($this->response->fields,
                             array('blue' => 'star',
                                   'mode' => 'id_res',
                                   'mj12.bright' => 'potato'));
        $this->assertEquals($this->response->signed,
                            array('mode', 'identity', 'return_to',
                                  'mj12.bright'));
    }

    function test_addFieldUnsigned()
    {
        $namespace = 'mj12';
        $this->response->addField($namespace, 'dull', 'lemon', false);
        $this->assertEquals($this->response->fields,
                            array('blue' => 'star',
                                  'mode' => 'id_res',
                                  'mj12.dull' => 'lemon'));
        $this->assertEquals($this->response->signed,
                            array('mode', 'identity', 'return_to'));
    }

    function test_addFields()
    {
        $namespace = 'mi5';
        $this->response->addFields($namespace, array('tangy' => 'suspenders',
                                                     'bravo' => 'inclusion'));
        $this->assertEquals($this->response->fields,
                            array('blue' => 'star',
                                  'mode' => 'id_res',
                                  'mi5.tangy' => 'suspenders',
                                  'mi5.bravo' => 'inclusion'));
        $this->assertEquals($this->response->signed,
                            array('mode', 'identity', 'return_to',
                                  'mi5.tangy', 'mi5.bravo'));
    }

    function test_addFieldsUnsigned()
    {
        $namespace = 'mi5';
        $this->response->addFields($namespace, array('strange' => 'conditioner',
                                                     'elemental' => 'blender'),
                                   false);
        $this->assertEquals($this->response->fields,
                            array('blue' => 'star',
                                  'mode' => 'id_res',
                                  'mi5.strange' => 'conditioner',
                                  'mi5.elemental' => 'blender'));
        $this->assertEquals($this->response->signed,
                            array('mode', 'identity', 'return_to'));
    }

    function test_update()
    {
        $eresponse = new Auth_OpenID_ServerResponse(null);
        $eresponse->fields = array('shape' => 'heart',
                                   'content' => 'strings,wire');
        $eresponse->signed = array('content');
        $this->response->update('box', $eresponse);
        $this->assertEquals($this->response->fields,
                            array('blue' => 'star',
                                  'mode' => 'id_res',
                                  'box.shape' => 'heart',
                                  'box.content' => 'strings,wire'));
        $this->assertEquals($this->response->signed,
                            array('mode', 'identity', 'return_to', 'content'));
    }
}

class _MockSignatory {
    var $isValid = true;

    function _MockSignatory($assoc)
    {
        $this->assocs = array($assoc);
    }

    function verify($assoc_handle, $sig, $signed_pairs)
    {
        if (!$sig) {
            return false;
        }

        if (!is_array($signed_pairs)) {
            return false;
        }

        if (in_array(array(true, $assoc_handle), $this->assocs)) {
            return $this->isValid;
        } else {
            return false;
        }
    }

    function getAssociation($assoc_handle, $dumb)
    {
        if (in_array(array($dumb, $assoc_handle), $this->assocs)) {
            // This isn't a valid implementation for many uses of this
            // function, mind you.
            return true;
        } else {
            return null;
        }
    }

    function invalidate($assoc_handle, $dumb)
    {
        if (in_array(array($dumb, $assoc_handle), $this->assocs)) {
            $i = 0;
            foreach ($this->assocs as $pair) {
                if ($pair == array($dumb, $assoc_handle)) {
                    unset($this->assocs[$i]);
                    break;
                }
                $i++;
            }
        }
    }
}

class Tests_Auth_OpenID_CheckAuth extends PHPUnit_TestCase {
    function setUp()
    {
        $this->assoc_handle = 'mooooooooo';
        $this->request = new Auth_OpenID_CheckAuthRequest(
            $this->assoc_handle, 'signarture',
            array(array('one', 'alpha'),
                  array('two', 'beta')));

        $this->signatory = new _MockSignatory(array(true, $this->assoc_handle));
    }

    function test_valid()
    {
        $r = $this->request->answer($this->signatory);
        $this->assertEquals($r->fields, array('is_valid' => 'true'));
        $this->assertEquals($r->request, $this->request);
    }

    function test_invalid()
    {
        $this->signatory->isValid = false;
        $r = $this->request->answer($this->signatory);
        $this->assertEquals($r->fields, array('is_valid' => 'false'));
    }

    function test_replay()
    {
        $r = $this->request->answer($this->signatory);
        $r = $this->request->answer($this->signatory);
        $this->assertEquals($r->fields, array('is_valid' => 'false'));
    }

    function test_invalidatehandle()
    {
        $this->request->invalidate_handle = "bogusHandle";
        $r = $this->request->answer($this->signatory);
        $this->assertEquals($r->fields,
                            array('is_valid' => 'true',
                                  'invalidate_handle' => "bogusHandle"));
        $this->assertEquals($r->request, $this->request);
    }

    function test_invalidatehandleNo()
    {
        $assoc_handle = 'goodhandle';
        $this->signatory->assocs[] = array(false, 'goodhandle');
        $this->request->invalidate_handle = $assoc_handle;
        $r = $this->request->answer($this->signatory);
        $this->assertEquals($r->fields, array('is_valid' => 'true'));
    }
}

class Tests_Auth_OpenID_Associate extends PHPUnit_TestCase {
    // TODO: test DH with non-default values for modulus and gen.
    // (important to do because we actually had it broken for a
    // while.)

    function setUp()
    {
        $this->request = Auth_OpenID_AssociateRequest::fromQuery(array());
        $this->store = new Tests_Auth_OpenID_MemStore();
        $this->signatory = new Auth_OpenID_Signatory($this->store);
        $this->assoc = $this->signatory->createAssociation(false);
    }

    function test_dh()
    {
        if (!defined('Auth_OpenID_NO_MATH_SUPPORT')) {
            $dh = new Auth_OpenID_DiffieHellman();
            $ml =& Auth_OpenID_getMathLib();

            $cpub = $dh->public;
            $session = new Auth_OpenID_DiffieHellmanServerSession(
                                           new Auth_OpenID_DiffieHellman(),
                                           $cpub);

            $this->request = new Auth_OpenID_AssociateRequest($session);
            $response = $this->request->answer($this->assoc);

            $this->assertEquals(
                      Auth_OpenID::arrayGet($response->fields, "assoc_type"),
                      "HMAC-SHA1");

            $this->assertEquals(
                      Auth_OpenID::arrayGet($response->fields, "assoc_handle"),
                      $this->assoc->handle);

            $this->assertFalse(
                      Auth_OpenID::arrayGet($response->fields, "mac_key"));

            $this->assertEquals(
                      Auth_OpenID::arrayGet($response->fields, "session_type"),
                      "DH-SHA1");

            $this->assertTrue(
                      Auth_OpenID::arrayGet($response->fields, "enc_mac_key"));

            $this->assertTrue(
                      Auth_OpenID::arrayGet($response->fields,
                                            "dh_server_public"));

            $enc_key = base64_decode(
                      Auth_OpenID::arrayGet($response->fields, "enc_mac_key"));

            $spub = $ml->base64ToLong(
                      Auth_OpenID::arrayGet($response->fields,
                                            "dh_server_public"));

            $secret = $dh->xorSecret($spub, $enc_key);

            $this->assertEquals($secret, $this->assoc->secret);
        }
    }

    function test_plaintext()
    {
        $response = $this->request->answer($this->assoc);

        $this->assertEquals(
                     Auth_OpenID::arrayGet($response->fields, "assoc_type"),
                     "HMAC-SHA1");

        $this->assertEquals(
                     Auth_OpenID::arrayGet($response->fields, "assoc_handle"),
                     $this->assoc->handle);

        $this->assertEquals(
            Auth_OpenID::arrayGet($response->fields, "expires_in"),
            sprintf("%d", $this->signatory->SECRET_LIFETIME));

        $this->assertEquals(
            Auth_OpenID::arrayGet($response->fields, "mac_key"),
            base64_encode($this->assoc->secret));

        $this->assertFalse(Auth_OpenID::arrayGet($response->fields,
                                                 "session_type"));

        $this->assertFalse(Auth_OpenID::arrayGet($response->fields,
                                                 "enc_mac_key"));

        $this->assertFalse(Auth_OpenID::arrayGet($response->fields,
                                                 "dh_server_public"));
    }
}

class Counter {
    function Counter()
    {
        $this->count = 0;
    }

    function inc()
    {
        $this->count += 1;
    }
}

class Tests_Auth_OpenID_ServerTest extends PHPUnit_TestCase {
    function setUp()
    {
        $this->store = new Tests_Auth_OpenID_MemStore();
        $this->server = new Auth_OpenID_Server($this->store);
    }

    function test_associate()
    {
        if (!defined('Auth_OpenID_NO_MATH_SUPPORT')) {
            $request = Auth_OpenID_AssociateRequest::fromQuery(array());
            $response = $this->server->openid_associate($request);
            $this->assertTrue(array_key_exists('assoc_handle',
                                               $response->fields));
        }
    }

    function test_checkAuth()
    {
        $request = new Auth_OpenID_CheckAuthRequest('arrrrrf',
                                                    '0x3999', array());

        $response = $this->server->openid_check_authentication($request);
        $this->assertTrue(array_key_exists('is_valid',
                                           $response->fields));
    }
}

class Tests_Auth_OpenID_Signatory extends PHPUnit_TestCase {
    function setUp()
    {
        $this->store =& new Tests_Auth_OpenID_MemStore();
        $this->signatory =& new Auth_OpenID_Signatory($this->store);
        $this->dumb_key = $this->signatory->dumb_key;
        $this->normal_key = $this->signatory->normal_key;
    }

    function test_sign()
    {
        $request = new Auth_OpenID_ServerRequest();
        $assoc_handle = '{assoc}{lookatme}';
        $assoc = Auth_OpenID_Association::fromExpiresIn(60, $assoc_handle,
                                                        'sekrit', 'HMAC-SHA1');
        $this->store->storeAssociation($this->normal_key, $assoc);
        $request->assoc_handle = $assoc_handle;
        $response = new Auth_OpenID_CheckIDResponse($request);
        $response->fields = array(
            'foo' => 'amsigned',
            'bar' => 'notsigned',
            'azu' => 'alsosigned');

        $response->signed = array('foo', 'azu');
        $sresponse = $this->signatory->sign($response);

        $this->assertEquals(Auth_OpenID::arrayGet($sresponse->fields,
                                                  'assoc_handle'),
                            $assoc_handle);

        $this->assertEquals(Auth_OpenID::arrayGet($sresponse->fields, 'signed'),
                            'foo,azu');

        $this->assertTrue(Auth_OpenID::arrayGet($sresponse->fields, 'sig'));
    }

    function test_signDumb()
    {
        $request = new Auth_OpenID_ServerRequest();
        $request->assoc_handle = null;
        $response = new Auth_OpenID_CheckIDResponse($request);
        $response->fields = array(
            'foo' => 'amsigned',
            'bar' => 'notsigned',
            'azu' => 'alsosigned');

        $response->signed = array('foo', 'azu');
        $sresponse = $this->signatory->sign($response);

        $assoc_handle = Auth_OpenID::arrayGet($sresponse->fields,
                                              'assoc_handle');

        $this->assertTrue($assoc_handle);
        $assoc = $this->signatory->getAssociation($assoc_handle, true);

        $this->assertTrue($assoc);
        $this->assertEquals(Auth_OpenID::arrayGet($sresponse->fields, 'signed'),
                            'foo,azu');
        $this->assertTrue(Auth_OpenID::arrayGet($sresponse->fields, 'sig'));
    }

    function test_signExpired()
    {
        $request = new Auth_OpenID_ServerRequest();
        $assoc_handle = '{assoc}{lookatme}';
        $assoc = Auth_OpenID_Association::fromExpiresIn(-10, $assoc_handle,
                                                        'sekrit', 'HMAC-SHA1');
        $this->store->storeAssociation($this->normal_key, $assoc);
        $this->assertTrue($this->store->getAssociation($this->normal_key,
                                                       $assoc_handle));

        $request->assoc_handle = $assoc_handle;
        $response = new Auth_OpenID_CheckIDResponse($request);
        $response->fields = array(
            'foo' => 'amsigned',
            'bar' => 'notsigned',
            'azu' => 'alsosigned');

        $response->signed = array('foo', 'azu');
        $sresponse = $this->signatory->sign($response);

        $new_assoc_handle = Auth_OpenID::arrayGet($sresponse->fields,
                                                  'assoc_handle');
        $this->assertTrue($new_assoc_handle);
        $this->assertFalse($new_assoc_handle == $assoc_handle);

        $this->assertEquals(Auth_OpenID::arrayGet($sresponse->fields,
                                                  'invalidate_handle'),
                            $assoc_handle);

        $this->assertEquals(Auth_OpenID::arrayGet($sresponse->fields, 'signed'),
                            'foo,azu');
        $this->assertTrue(Auth_OpenID::arrayGet($sresponse->fields, 'sig'));

        // make sure the expired association is gone
        $this->assertFalse($this->store->getAssociation($this->normal_key,
                                                        $assoc_handle));

        // make sure the new key is a dumb mode association
        $this->assertTrue($this->store->getAssociation($this->dumb_key,
                                                       $new_assoc_handle));

        $this->assertFalse($this->store->getAssociation($this->normal_key,
                                                        $new_assoc_handle));
    }

    function test_signInvalidHandle()
    {
        $request = new Auth_OpenID_ServerRequest();
        $assoc_handle = '{bogus-assoc}{notvalid}';

        $request->assoc_handle = $assoc_handle;
        $response = new Auth_OpenID_CheckIDResponse($request);
        $response->fields = array(
            'foo' => 'amsigned',
            'bar' => 'notsigned',
            'azu' => 'alsosigned');

        $response->signed = array('foo', 'azu');
        $sresponse = $this->signatory->sign($response);

        $new_assoc_handle = Auth_OpenID::arrayGet($sresponse->fields,
                                                  'assoc_handle');

        $this->assertTrue($new_assoc_handle);
        $this->assertFalse($new_assoc_handle == $assoc_handle);

        $this->assertEquals(Auth_OpenID::arrayGet($sresponse->fields,
                                                  'invalidate_handle'),
                            $assoc_handle);

        $this->assertEquals(Auth_OpenID::arrayGet($sresponse->fields, 'signed'),
                            'foo,azu');
        $this->assertTrue(Auth_OpenID::arrayGet($sresponse->fields, 'sig'));

        // make sure the new key is a dumb mode association
        $this->assertTrue($this->store->getAssociation($this->dumb_key,
                                                       $new_assoc_handle));

        $this->assertFalse($this->store->getAssociation($this->normal_key,
                                                        $new_assoc_handle));
    }

    function test_verify()
    {
        $assoc_handle = '{vroom}{zoom}';
        $assoc = Auth_OpenID_Association::fromExpiresIn(60, $assoc_handle,
                                                        'sekrit', 'HMAC-SHA1');

        $this->store->storeAssociation($this->dumb_key, $assoc);

        $signed_pairs = array(array('foo', 'bar'),
                              array('apple', 'orange'));

        $sig = "Ylu0KcIR7PvNegB/K41KpnRgJl0=";
        $verified = $this->signatory->verify($assoc_handle, $sig,
                                             $signed_pairs);
        $this->assertTrue($verified);
    }

    function test_verifyBadSig()
    {
        $assoc_handle = '{vroom}{zoom}';
        $assoc = Auth_OpenID_Association::fromExpiresIn(60, $assoc_handle,
                                                        'sekrit', 'HMAC-SHA1');

        $this->store->storeAssociation($this->dumb_key, $assoc);

        $signed_pairs = array(array('foo', 'bar'),
                              array('apple', 'orange'));

        $sig = str_rot13("Ylu0KcIR7PvNegB/K41KpnRgJl0=");
        $verified = $this->signatory->verify($assoc_handle, $sig,
                                             $signed_pairs);

        $this->assertFalse($verified);
    }

    function test_verifyBadHandle()
    {
        $assoc_handle = '{vroom}{zoom}';
        $signed_pairs = array(array('foo', 'bar'),
                              array('apple', 'orange'));

        $sig = "Ylu0KcIR7PvNegB/K41KpnRgJl0=";
        $verified = $this->signatory->verify($assoc_handle, $sig,
                                             $signed_pairs);
        $this->assertFalse($verified);
    }

    function test_getAssoc()
    {
        $assoc_handle = $this->makeAssoc(true);
        $assoc = $this->signatory->getAssociation($assoc_handle, true);
        $this->assertTrue($assoc);
        $this->assertEquals($assoc->handle, $assoc_handle);
    }

    function test_getAssocExpired()
    {
        $assoc_handle = $this->makeAssoc(true, -10);
        $assoc = $this->signatory->getAssociation($assoc_handle, true);
        $this->assertFalse($assoc);
    }

    function test_getAssocInvalid()
    {
        $ah = 'no-such-handle';
        $this->assertEquals(
            $this->signatory->getAssociation($ah, false), null);
    }

    function test_getAssocDumbVsNormal()
    {
        $assoc_handle = $this->makeAssoc(true);
        $this->assertEquals(
            $this->signatory->getAssociation($assoc_handle, false), null);
    }

    function test_createAssociation()
    {
        $assoc = $this->signatory->createAssociation(false);
        $this->assertTrue($this->signatory->getAssociation($assoc->handle,
                                                           false));
    }

    function makeAssoc($dumb, $lifetime = 60)
    {
        $assoc_handle = '{bling}';
        $assoc = Auth_OpenID_Association::fromExpiresIn(
                                               $lifetime, $assoc_handle,
                                               'sekrit', 'HMAC-SHA1');

        $this->store->storeAssociation((($dumb) ? $this->dumb_key :
                                        $this->normal_key), $assoc);
        return $assoc_handle;
    }

    function test_invalidate()
    {
        $assoc_handle = '-squash-';
        $assoc = Auth_OpenID_Association::fromExpiresIn(60, $assoc_handle,
                                                        'sekrit', 'HMAC-SHA1');

        $this->store->storeAssociation($this->dumb_key, $assoc);
        $assoc = $this->signatory->getAssociation($assoc_handle, true);
        $this->assertTrue($assoc);
        $assoc = $this->signatory->getAssociation($assoc_handle, true);
        $this->assertTrue($assoc);
        $this->signatory->invalidate($assoc_handle, true);
        $assoc = $this->signatory->getAssociation($assoc_handle, true);
        $this->assertFalse($assoc);
    }
}

class Tests_Auth_OpenID_Server extends PHPUnit_TestSuite {

    function getName()
    {
        return "Tests_Auth_OpenID_Server";
    }

    function Tests_Auth_OpenID_Server()
    {
        $this->addTestSuite('Tests_Auth_OpenID_Signatory');
        $this->addTestSuite('Tests_Auth_OpenID_ServerTest');
        if (!defined('Auth_OpenID_NO_MATH_SUPPORT')) {
            $this->addTestSuite('Tests_Auth_OpenID_Associate');
        }
        $this->addTestSuite('Tests_Auth_OpenID_CheckAuth');
        $this->addTestSuite('Tests_Auth_OpenID_CheckIDExtension');
        $this->addTestSuite('Tests_Auth_OpenID_CheckAuth');
        $this->addTestSuite('Tests_Auth_OpenID_SigningEncode');
        $this->addTestSuite('Tests_Auth_OpenID_Test_Encode');
        $this->addTestSuite('Tests_Auth_OpenID_Test_Decode');
        $this->addTestSuite('Tests_Auth_OpenID_Test_ServerError');
        $this->addTestSuite('Tests_Auth_OpenID_CheckID');
    }
}

?>