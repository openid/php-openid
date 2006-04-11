<?php

/**
 * A test script for the OpenIDStore classes.
 *
 * PHP versions 4 and 5
 *
 * LICENSE: See the COPYING file included in this distribution.
 *
 * @package OpenID
 * @author JanRain, Inc. <openid@janrain.com>
 * @copyright 2005 Janrain, Inc.
 * @license http://www.gnu.org/copyleft/lesser.html LGPL
 */

/**
 * Require classes and functions to run the Store tests.
 */
require_once 'Auth/OpenID/Association.php';
require_once 'Auth/OpenID/CryptUtil.php';
require_once 'PHPUnit.php';

/**
 * This is the host where the SQL stores' databases should be created
 * and destroyed.
 */
$_Auth_OpenID_db_test_host = 'dbtest';

/**
 * Generate a sufficently unique database name so many hosts can run
 * SQL store tests on the server at the same time and not step on each
 * other.
 */
function _Auth_OpenID_getTmpDbName()
{
    $hostname = php_uname('n');
    $hostname = str_replace('.', '_', $hostname);

    return sprintf("%s_%d_%s_openid_test",
                   $hostname,
                   getmypid(),
                   strval(rand(1, time())));
}

/**
 * Tests the OpenID stores.
 *
 * @package OpenID
 */
class Tests_Auth_OpenID_StoreTest extends PHPUnit_TestCase {

    /**
     * Prepares for the SQL store tests.
     */
    function setUp()
    {
        $this->letters = Auth_OpenID_letters;
        $this->digits = Auth_OpenID_digits;
        $this->punct = Auth_OpenID_punct;
        $this->allowed_nonce = $this->letters . $this->digits;
        $this->allowed_handle = $this->letters . $this->digits . $this->punct;
    }

    /**
     * Generates a nonce value.
     */
    function generateNonce()
    {
        return Auth_OpenID_CryptUtil::randomString(8, $this->allowed_nonce);
    }

    /**
     * Generates an association with the specified parameters.
     */
    function genAssoc($now, $issued = 0, $lifetime = 600)
    {
        $sec = Auth_OpenID_CryptUtil::randomString(20);
        $hdl = Auth_OpenID_CryptUtil::randomString(128, $this->allowed_handle);
        return new Auth_OpenID_Association($hdl, $sec, $now + $issued,
                                          $lifetime, 'HMAC-SHA1');
    }

    /**
     * @access private
     */
    function _checkRetrieve(&$store, $url, $handle, $expected, $name = null)
    {
        $retrieved_assoc = $store->getAssociation($url, $handle);
        if (($expected === null) || ($store->isDumb())) {
            $this->assertNull($retrieved_assoc, "Retrieved association " .
                              "was non-null");
        } else {
            if ($retrieved_assoc === null) {
                $this->fail("$name: Got null when expecting " .
                            $expected->serialize());
            } else {
                $this->assertEquals($expected->serialize(),
                                    $retrieved_assoc->serialize(), $name);
            }
        }
    }

    function _checkRemove(&$store, $url, $handle, $expected, $name = null)
    {
        $present = $store->removeAssociation($url, $handle);
        $expectedPresent = (!$store->isDumb() && $expected);
        $this->assertTrue((!$expectedPresent && !$present) ||
                          ($expectedPresent && $present),
                          $name);
    }

    /**
     * Make sure a given store has a minimum of API compliance. Call
     * this function with an empty store.
     *
     * Raises AssertionError if the store does not work as expected.
     *
     * OpenIDStore -> NoneType
     */
    function _testStore($store)
    {

        // Association functions
        $now = time();

        $server_url = 'http://www.myopenid.com/openid';

        $assoc = $this->genAssoc($now);

        $this->_checkRetrieve($store, $server_url, null, null,
            'Make sure that a missing association returns no result');

        $store->storeAssociation($server_url, $assoc);
        $this->_checkRetrieve($store, $server_url, null, $assoc,
            'Check that after storage, getting returns the same result');

        $this->_checkRetrieve($store, $server_url, null, $assoc,
            'more than once');

        $store->storeAssociation($server_url, $assoc);
        $this->_checkRetrieve($store, $server_url, null, $assoc,
            'Storing more than once has no ill effect');

        // Removing an association that does not exist returns not present
        $this->_checkRemove($store, $server_url, $assoc->handle . 'x', false,
                            "Remove nonexistent association (1)");

        // Removing an association that does not exist returns not present
        $this->_checkRemove($store, $server_url . 'x', $assoc->handle, false,
                            "Remove nonexistent association (2)");

        // Removing an association that is present returns present
        $this->_checkRemove($store, $server_url, $assoc->handle, true,
                            "Remove existent association");

        // but not present on subsequent calls
        $this->_checkRemove($store, $server_url, $assoc->handle, false,
                            "Remove nonexistent association after removal");

        // Put assoc back in the store
        $store->storeAssociation($server_url, $assoc);

        // More recent and expires after assoc
        $assoc2 = $this->genAssoc($now, $issued = 1);
        $store->storeAssociation($server_url, $assoc2);

        $this->_checkRetrieve($store, $server_url, null, $assoc2,
            'After storing an association with a different handle, but the
same $server_url, the handle with the later expiration is
returned.');

        $this->_checkRetrieve($store, $server_url, $assoc->handle, $assoc,
            'We can still retrieve the older association');

        $this->_checkRetrieve($store, $server_url, $assoc2->handle, $assoc2,
            'Plus we can retrieve the association with the later expiration
explicitly');

        $assoc3 = $this->genAssoc($now, $issued = 2, $lifetime = 100);
        $store->storeAssociation($server_url, $assoc3);

        // More recent issued time, so assoc3 is expected.
        $this->_checkRetrieve($store, $server_url, null, $assoc3, "(1)");

        $this->_checkRetrieve($store, $server_url, $assoc->handle,
                              $assoc, "(2)");

        $this->_checkRetrieve($store, $server_url, $assoc2->handle,
                              $assoc2, "(3)");

        $this->_checkRetrieve($store, $server_url, $assoc3->handle,
                              $assoc3, "(4)");

        $this->_checkRemove($store, $server_url, $assoc2->handle, true, "(5)");

        $this->_checkRetrieve($store, $server_url, null, $assoc3, "(6)");

        $this->_checkRetrieve($store, $server_url, $assoc->handle,
                              $assoc, "(7)");

        $this->_checkRetrieve($store, $server_url, $assoc2->handle,
                              null, "(8)");

        $this->_checkRetrieve($store, $server_url, $assoc3->handle,
                              $assoc3, "(9)");

        $this->_checkRemove($store, $server_url, $assoc2->handle,
                            false, "(10)");

        $this->_checkRemove($store, $server_url, $assoc3->handle,
                            true, "(11)");

        $this->_checkRetrieve($store, $server_url, null, $assoc, "(12)");

        $this->_checkRetrieve($store, $server_url, $assoc->handle,
                              $assoc, "(13)");

        $this->_checkRetrieve($store, $server_url, $assoc2->handle,
                              null, "(14)");

        $this->_checkRetrieve($store, $server_url, $assoc3->handle,
                              null, "(15)");

        $this->_checkRemove($store, $server_url, $assoc2->handle,
                            false, "(16)");

        $this->_checkRemove($store, $server_url, $assoc->handle,
                            true, "(17)");

        $this->_checkRemove($store, $server_url, $assoc3->handle,
                            false, "(18)");

        $this->_checkRetrieve($store, $server_url, null, null, "(19)");

        $this->_checkRetrieve($store, $server_url, $assoc->handle,
                              null, "(20)");

        $this->_checkRetrieve($store, $server_url, $assoc2->handle,
                              null, "(21)");

        $this->_checkRetrieve($store, $server_url,$assoc3->handle,
                              null, "(22)");

        $this->_checkRemove($store, $server_url, $assoc2->handle,
                            false, "(23)");

        $this->_checkRemove($store, $server_url, $assoc->handle,
                            false, "(24)");

        $this->_checkRemove($store, $server_url, $assoc3->handle,
                            false, "(25)");
    }

    function _checkUseNonce(&$store, $nonce, $expected, $msg=null)
    {
        $actual = $store->useNonce($nonce);
        $expected = $store->isDumb() || $expected;
        $this->assertTrue(($actual && $expected) || (!$actual && !$expected),
                          "_checkUseNonce failed: $msg");
    }

    function _testNonce(&$store)
    {
        // Nonce functions

        // Random nonce (not in store)
        $nonce1 = $this->generateNonce();

        // A nonce is not present by default
        $this->_checkUseNonce($store, $nonce1, false, 1);

        // Storing once causes useNonce to return true the first, and
        // only the first, time it is called after the $store->
        $store->storeNonce($nonce1);
        $this->_checkUseNonce($store, $nonce1, true, 2);
        $this->_checkUseNonce($store, $nonce1, false, 3);
        $this->_checkUseNonce($store, $nonce1, false, 4);

        // Storing twice has the same effect as storing once.
        $store->storeNonce($nonce1);
        $store->storeNonce($nonce1);
        $this->_checkUseNonce($store, $nonce1, true, 5);
        $this->_checkUseNonce($store, $nonce1, false, 6);
        $this->_checkUseNonce($store, $nonce1, false, 7);

        // Auth key functions

        // There is no key to start with, so generate a new key and
        // return it.
        $key = $store->getAuthKey();

        // The second time around should return the same as last time.
        $key2 = $store->getAuthKey();
        $this->assertEquals($key, $key2, "Auth keys differ");
        $this->assertEquals(strlen($key), $store->AUTH_KEY_LEN,
                            "Key length not equals AUTH_KEY_LEN");
    }

    function test_memstore()
    {
        require_once 'Tests/Auth/OpenID/MemStore.php';
        $store = new Tests_Auth_OpenID_MemStore('Bogus auth key      ');
        $this->_testStore(&$store);
        $this->_testNonce(&$store);
    }

    function test_filestore()
    {
        require_once 'Auth/OpenID/FileStore.php';

        $temp_dir = Auth_OpenID_FileStore::_mkdtemp('/tmp');

        if (!$temp_dir) {
            trigger_error('Could not create temporary directory ' .
                          'with Auth_OpenID_FileStore::_mkdtemp',
                          E_USER_WARNING);
            return null;
        }

        $store = new Auth_OpenID_FileStore($temp_dir);
        $this->_testStore($store);
        $this->_testNonce($store);
        $store->destroy();
    }

    function test_postgresqlstore()
    {
        // If the postgres extension isn't loaded or loadable, succeed
        // because we can't run the test.
        if (!(extension_loaded('pgsql') ||
              @dl('pgsql.' . PHP_SHLIB_SUFFIX))) {
            $this->pass();
            return;
        }

        require_once 'Auth/OpenID/PostgreSQLStore.php';
        require_once 'DB.php';

        global $_Auth_OpenID_db_test_host;

        $temp_db_name = _Auth_OpenID_getTmpDbName();

        $dsn = array(
                     'phptype'  => 'pgsql',
                     'username' => 'openid_test',
                     'password' => '',
                     'hostspec' => $_Auth_OpenID_db_test_host,
                     'database' => 'template1'
                     );

        $template_db =& DB::connect($dsn);

        if (PEAR::isError($template_db)) {
            $this->fail("PostgreSQL template1 database connection failed: " .
                        $template_db->getMessage());
            return;
        }

        $allowed_failures = 5;
        $failures = 0;
        $success = false;

        while (($failures < $allowed_failures) && !$success) {
            // Try to create the test database.
            $result = $template_db->query(sprintf("CREATE DATABASE %s",
                                                  $temp_db_name));

            if (PEAR::isError($result)) {
                $failures++;
                sleep(3 * ($failures + 1));
            } else {
                $success = true;
            }
        }

        if (!$success) {
            $this->fail("Temporary database creation failed after $failures ".
                        " tries ('$temp_db_name'): " . $result->getMessage());
            return;
        }

        $template_db->disconnect();
        unset($template_db);

        // Disconnect from template1 and reconnect to the temporary
        // testing database.
        $dsn['database'] = $temp_db_name;
        $db =& DB::connect($dsn);

        if (PEAR::isError($db)) {
            $this->fail("Temporary database connection failed " .
                        " ('$temp_db_name'): " . $db->getMessage());
            return;
        }

        $store =& new Auth_OpenID_PostgreSQLStore($db);
        $store->createTables();
        $this->_testStore($store);
        $this->_testNonce($store);

        $db->disconnect();
        unset($db);

        // Connect to template1 again so we can drop the temporary
        // database.
        $dsn['database'] = 'template1';
        $template_db =& DB::connect($dsn);

        if (PEAR::isError($template_db)) {
            $this->fail("Template database connection (to drop " .
                        "temporary database) failed: " .
                        $template_db->getMessage());
            return;
        }

        $result = $template_db->query(sprintf("DROP DATABASE %s",
                                              $temp_db_name));

        if (PEAR::isError($result)) {
            $this->fail("Dropping temporary database failed: " .
                        $result->getMessage());
            return;
        }

        $template_db->disconnect();
    }

    function test_sqlitestore()
    {
        // If the postgres extension isn't loaded or loadable, succeed
        // because we can't run the test.
        if (!(extension_loaded('sqlite') ||
              @dl('sqlite.' . PHP_SHLIB_SUFFIX))) {
            $this->pass();
            return;
        }

        require_once 'Auth/OpenID/SQLiteStore.php';
        require_once 'DB.php';

        $temp_dir = Auth_OpenID_FileStore::_mkdtemp('/tmp');

        if (!$temp_dir) {
            trigger_error('Could not create temporary directory ' .
                          'with Auth_OpenID_FileStore::_mkdtemp',
                          E_USER_WARNING);
            return null;
        }

        $dsn = sprintf("sqlite:///%s/file.db", $temp_dir);
        $db =& DB::connect($dsn);

        if (PEAR::isError($db)) {
            $this->fail("SQLite database connection failed: " .
                        $db->getMessage());
            return;
        }

        $store =& new Auth_OpenID_SQLiteStore($db);
        $this->assertTrue($store->createTables(), "Table creation failed");
        $this->_testStore($store);
        $this->_testNonce($store);
    }

    function test_mysqlstore()
    {
        // If the mysql extension isn't loaded or loadable, succeed
        // because we can't run the test.
        if (!(extension_loaded('mysql') ||
              @dl('mysql.' . PHP_SHLIB_SUFFIX))) {
            $this->pass();
            return;
        }

        require_once 'Auth/OpenID/MySQLStore.php';
        require_once 'DB.php';

        global $_Auth_OpenID_db_test_host;

        $dsn = array(
                     'phptype'  => 'mysql',
                     'username' => 'openid_test',
                     'password' => '',
                     'hostspec' => $_Auth_OpenID_db_test_host
                     );

        $db =& DB::connect($dsn);

        if (PEAR::isError($db)) {
            $this->fail("MySQL database connection failed: " .
                        $db->getMessage());
            return;
        }

        $temp_db_name = _Auth_OpenID_getTmpDbName();

        $result = $db->query("CREATE DATABASE $temp_db_name");

        if (PEAR::isError($result)) {
            $this->fail("Error creating MySQL temporary database: " .
                        $result->getMessage());
            return;
        }

        $db->query("USE $temp_db_name");

        $store =& new Auth_OpenID_MySQLStore($db);
        $store->createTables();
        $this->_testStore($store);
        $this->_testNonce($store);

        $db->query("DROP DATABASE $temp_db_name");
    }
}

?>
