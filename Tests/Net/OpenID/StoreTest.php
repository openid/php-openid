<?php

require_once('Net/OpenID/Association.php');
require_once('Net/OpenID/CryptUtil.php');

function Net_OpenID_rmtree($dir) {
    if ($dir[strlen($dir) - 1] != DIRECTORY_SEPARATOR) {
        $dir .= DIRECTORY_SEPARATOR;
    }

    if ($handle = opendir($dir)) {
        while ($item = readdir($handle)) {
            if (!in_array($item, array('.', '..'))) {
                if (is_dir($dir . $item)) {
                    if (!Net_OpenID_rmtree($dir . $item)) {
                        return false;
                    }
                } else if (is_file($dir . $item)) {
                    if (!unlink($dir . $item)) {
                        return false;
                    }
                }
            }
        }

        closedir($handle);

        if (!@rmdir($dir)) {
            return false;
        }

        return true;
    } else {
        // Couldn't open directory.
        return false;
    }
}

class Tests_Net_OpenID_StoreTest extends PHPUnit_TestCase {

    function setUp() {
        $this->letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        $this->digits = "0123456789";
        $this->punct = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
        $this->allowed_nonce = $this->letters . $this->digits;
        $this->allowed_handle = $this->letters . $this->digits . $this->punct;
    }

    function generateNonce() {
        return Net_OpenID_CryptUtil::randomString(8, $this->allowed_nonce);
    }

    function genAssoc($now, $issued = 0, $lifetime = 600) {
        $sec = call_user_func(array('Net_OpenID_CryptUtil', 'randomString'),
                              20);
        $hdl = Net_OpenID_CryptUtil::randomString(128, $this->allowed_handle);
        return new Net_OpenID_Association($hdl, $sec, $now + $issued, $lifetime,
                                          'HMAC-SHA1');
    }

    /**
     * Make sure a given store has a minimum of API compliance. Call
     * this function with an empty store.
     *
     * Raises AssertionError if the store does not work as expected.
     *
     * OpenIDStore -> NoneType
     */
    function _testStore($store) {

        // Association functions
        $now = time();

        $server_url = 'http://www.myopenid.com/openid';

        function checkRetrieve(&$store, $url,
                               $handle = null, $expected = null) {
            $retrieved_assoc = $store->getAssociation($url, $handle);
            if (($expected === null) || ($store->isDumb())) {
                assert($retrieved_assoc === null);
            } else {
                assert($retrieved_assoc == $expected);
                /**
                 * The following test doesn't mean the same thing in
                 * PHP that it does in Python.

                if ($retrieved_assoc === $expected) {
                    print 'Unexpected: retrieved a reference to the expected ' .
                        'value instead of a new object\n';
                }

                */
                assert($retrieved_assoc->handle == $expected->handle);
                assert($retrieved_assoc->secret == $expected->secret);
            }
        }

        function checkRemove(&$store, $url, $handle, $expected) {
            $present = $store->removeAssociation($url, $handle);
            $expectedPresent = (!$store->isDumb() && $expected);
            assert((!$expectedPresent && !$present) ||
                   ($expectedPresent && $present));
        }

        $assoc = $this->genAssoc($now);

        // Make sure that a missing association returns no result
        checkRetrieve($store, $server_url);

        // Check that after storage, getting returns the same result
        $store->storeAssociation($server_url, $assoc);
        checkRetrieve($store, $server_url, null, $assoc);

        // more than once
        checkRetrieve($store, $server_url, null, $assoc);

        // Storing more than once has no ill effect
        $store->storeAssociation($server_url, $assoc);
        checkRetrieve($store, $server_url, null, $assoc);

        // Removing an association that does not exist returns not present
        checkRemove($store, $server_url, $assoc->handle . 'x', false);

        // Removing an association that does not exist returns not present
        checkRemove($store, $server_url . 'x', $assoc->handle, false);

        // Removing an association that is present returns present
        checkRemove($store, $server_url, $assoc->handle, true);

        // but not present on subsequent calls
        checkRemove($store, $server_url, $assoc->handle, false);

        // Put assoc back in the store
        $store->storeAssociation($server_url, $assoc);

        // More recent and expires after assoc
        $assoc2 = $this->genAssoc($now, $issued = 1);
        $store->storeAssociation($server_url, $assoc2);

        // After storing an association with a different handle, but the
        // same $server_url, the handle with the later expiration is
        // returned.
        checkRetrieve($store, $server_url, null, $assoc2);

        // We can still retrieve the older association
        checkRetrieve($store, $server_url, $assoc->handle, $assoc);

        // Plus we can retrieve the association with the later expiration
        // explicitly
        checkRetrieve($store, $server_url, $assoc2->handle, $assoc2);

        // More recent, but expires earlier than assoc2 or assoc
        $assoc3 = $this->genAssoc($now, $issued = 2, $lifetime = 100);
        $store->storeAssociation($server_url, $assoc3);

        checkRetrieve($store, $server_url, null, $assoc3);
        checkRetrieve($store, $server_url, $assoc->handle, $assoc);
        checkRetrieve($store, $server_url, $assoc2->handle, $assoc2);
        checkRetrieve($store, $server_url, $assoc3->handle, $assoc3);

        checkRemove($store, $server_url, $assoc2->handle, true);

        checkRetrieve($store, $server_url, null, $assoc3);
        checkRetrieve($store, $server_url, $assoc->handle, $assoc);
        checkRetrieve($store, $server_url, $assoc2->handle, null);
        checkRetrieve($store, $server_url, $assoc3->handle, $assoc3);

        checkRemove($store, $server_url, $assoc2->handle, false);
        checkRemove($store, $server_url, $assoc3->handle, true);

        checkRetrieve($store, $server_url, null, $assoc);
        checkRetrieve($store, $server_url, $assoc->handle, $assoc);
        checkRetrieve($store, $server_url, $assoc2->handle, null);
        checkRetrieve($store, $server_url, $assoc3->handle, null);

        checkRemove($store, $server_url, $assoc2->handle, false);
        checkRemove($store, $server_url, $assoc->handle, true);
        checkRemove($store, $server_url, $assoc3->handle, false);
        checkRetrieve($store, $server_url, null, null);
        checkRetrieve($store, $server_url, $assoc->handle, null);
        checkRetrieve($store, $server_url, $assoc2->handle, null);
        checkRetrieve($store, $server_url,$assoc3->handle, null);

        checkRemove($store, $server_url, $assoc2->handle, False);
        checkRemove($store, $server_url, $assoc->handle, False);
        checkRemove($store, $server_url, $assoc3->handle, False);

        // Nonce functions

        function testUseNonce($store, $nonce, $expected) {
            $actual = $store->useNonce($nonce);
            $expected = $store->isDumb() || $expected;
            assert(($actual && $expected) || (!$actual && !$expected));
        }

        // Random nonce (not in store)
        $nonce1 = $this->generateNonce();

        // A nonce is not present by default
        testUseNonce($store, $nonce1, false);

        // Storing once causes useNonce to return True the first, and only
        // the first, time it is called after the $store->
        $store->storeNonce($nonce1);
        testUseNonce($store, $nonce1, true);
        testUseNonce($store, $nonce1, false);

        // Storing twice has the same effect as storing once.
        $store->storeNonce($nonce1);
        $store->storeNonce($nonce1);
        testUseNonce($store, $nonce1, True);
        testUseNonce($store, $nonce1, False);

        // Auth key functions

        // There is no key to start with, so generate a new key and return
        // it.
        $key = $store->getAuthKey();

        // The second time around should return the same as last time.
        $key2 = $store->getAuthKey();
        assert($key == $key2);
        assert(strlen($key) == $store->AUTH_KEY_LEN);
    }

    function test_filestore() {
        require_once('Net/OpenID/Store/FileStore.php');

        $temp_dir = Net_OpenID_mkdtemp('/tmp');

        if (!$temp_dir) {
            trigger_error('Could not create temporary directory ' .
                          'with Net_OpenID_mkdtemp', E_USER_WARNING);
            return null;
        }

        $store = new Net_OpenID_FileStore($temp_dir);
        $this->_testStore($store);
        Net_OpenID_rmtree($temp_dir);
    }
}

?>