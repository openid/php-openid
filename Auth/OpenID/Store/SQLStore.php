<?php

/**
 * A base class for SQL-backed OpenID stores.
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
 * Require the PEAR DB module because we'll need it for the SQL-based
 * stores implemented here.
 */
require_once 'DB.php';
require_once 'Interface.php';

/**
 * Converts a query result to a boolean.  If the result is a PEAR
 * error object, this returns false; otherwise, this returns true.
 */
function _resultToBool($obj)
{
    if (PEAR::isError($obj)) {
        return false;
    } else {
        return true;
    }
}

/**
 * "Octifies" a binary string by returning a string with escaped octal
 * bytes.  This is used for preparing binary data for PostgreSQL BYTEA
 * fields.
 */
function _octify($str)
{
    $result = "";
    for ($i = 0; $i < strlen($str); $i++) {
        $ch = substr($str, $i, 1);
        if ($ch == "\\") {
            $result .= "\\\\\\\\";
        } else if (ord($ch) == 0) {
            $result .= "\\\\000";
        } else {
            $result .= "\\" . strval(decoct(ord($ch)));
        }
    }
    return $result;
}

/**
 * "Unoctifies" octal-escaped data from PostgreSQL and returns the
 * resulting ASCII (possibly binary) string.
 */
function _unoctify($str)
{
    $result = "";
    $i = 0;
    while ($i < strlen($str)) {
        $char = $str[$i];
        if ($char == "\\") {
            // Look to see if the next char is a backslash and append
            // it.
            if ($str[$i + 1] != "\\") {
                $octal_digits = substr($str, $i + 1, 3);
                $dec = octdec($octal_digits);
                $char = chr($dec);
                $i += 4;
            } else {
                $char = "\\";
                $i += 2;
            }
        } else {
            $i += 1;
        }

        $result .= $char;
    }

    return $result;
}

/**
 * This is the parent class for the SQL stores, which contains the
 * logic common to all of the SQL stores.
 *
 * The table names used are determined by the class variables
 * settings_table_name, associations_table_name, and
 * nonces_table_name.  To change the name of the tables used, pass new
 * table names into the constructor.
 *
 * To create the tables with the proper schema, see the createTables
 * method.
 *
 * This class shouldn't be used directly.  Use one of its subclasses
 * instead, as those contain the code necessary to use a specific
 * database.
 *
 * All methods other than the constructor and createTables should be
 * considered implementation details.
 *
 * @access private
 * @package OpenID
 */
class Auth_OpenID_SQLStore extends Auth_OpenID_OpenIDStore {

    /**
     * This creates a new SQLStore instance.  It requires an
     * established database connection be given to it, and it allows
     * overriding the default table names.
     *
     * @param connection $conn This must be an established connection
     * to a database of the correct type for the SQLStore subclass
     * you're using.
     *
     * @param string $settings_table This is an optional parameter to
     * specify the name of the table used for this store's settings.
     * The default value is 'oid_settings'.
     *
     * @param associations_table: This is an optional parameter to
     * specify the name of the table used for storing associations.
     * The default value is 'oid_associations'.
     *
     * @param nonces_table: This is an optional parameter to specify
     * the name of the table used for storing nonces.  The default
     * value is 'oid_nonces'.
     */
    function Auth_OpenID_SQLStore($connection, $settings_table = null,
                                  $associations_table = null,
                                  $nonces_table = null)
    {
        $this->settings_table_name = "oid_settings";
        $this->associations_table_name = "oid_associations";
        $this->nonces_table_name = "oid_nonces";

        // Check the connection object type to be sure it's a PEAR
        // database connection.
        if (!(is_object($connection) &&
              is_subclass_of($connection, 'db_common'))) {
            trigger_error("Auth_OpenID_SQLStore expected PEAR connection " .
                          "object", E_USER_ERROR);
            return;
        }

        $this->connection = $connection;

        // Be sure to set the fetch mode so the results are keyed on
        // column name instead of column index.
        $this->connection->setFetchMode(DB_FETCHMODE_ASSOC);

        if ($settings_table) {
            $this->settings_table_name = $settings_table;
        }

        if ($associations_table) {
            $this->associations_table_name = $associations_table;
        }

        if ($nonces_table) {
            $this->nonces_table_name = $nonces_table;
        }

        $this->max_nonce_age = 6 * 60 * 60;

        // Be sure to run the database queries with auto-commit mode
        // turned OFF, because we want every function to run in a
        // transaction, implicitly.  As a rule, methods named with a
        // leading underscore will NOT control transaction behavior.
        // Callers of these methods will worry about transactions.
        $this->connection->autoCommit(false);

        // Create an empty SQL strings array.
        $this->sql = array();

        // Call this method (which should be overridden by subclasses)
        // to populate the $this->sql array with SQL strings.
        $this->setSQL();

        // Verify that all required SQL statements have been set, and
        // raise an error if any expected SQL strings were either
        // absent or empty.
        list($missing, $empty) = $this->_verifySQL();

        if ($missing) {
            trigger_error("Expected keys in SQL query list: " .
                          implode(", ", $missing),
                          E_USER_ERROR);
            return;
        }

        if ($empty) {
            trigger_error("SQL list keys have no SQL strings: " .
                          implode(", ", $empty),
                          E_USER_ERROR);
            return;
        }

        // Add table names to queries.
        $this->_fixSQL();
    }

    /**
     * This method should be overridden by subclasses.  This method is
     * called by the constructor to set values in $this->sql, which is
     * an array keyed on sql name.
     */
    function setSQL()
    {
    }

    /**
     * Resets the store by removing all records from the store's
     * tables.
     */
    function reset()
    {
        $this->connection->query(sprintf("DELETE FROM %s",
                                         $this->associations_table_name));

        $this->connection->query(sprintf("DELETE FROM %s",
                                         $this->nonces_table_name));

        $this->connection->query(sprintf("DELETE FROM %s",
                                         $this->settings_table_name));
    }

    /**
     * @access private
     */
    function _verifySQL()
    {
        $missing = array();
        $empty = array();

        $required_sql_keys = array(
                                   'nonce_table',
                                   'assoc_table',
                                   'settings_table',
                                   'get_auth',
                                   'create_auth',
                                   'set_assoc',
                                   'get_assoc',
                                   'get_assocs',
                                   'remove_assoc',
                                   'add_nonce',
                                   'get_nonce',
                                   'remove_nonce'
                                   );

        foreach ($required_sql_keys as $key) {
            if (!array_key_exists($key, $this->sql)) {
                $missing[] = $key;
            } else if (!$this->sql[$key]) {
                $empty[] = $key;
            }
        }

        return array($missing, $empty);
    }

    /**
     * @access private
     */
    function _fixSQL()
    {
        $replacements = array(
                              array(
                                    'value' => $this->nonces_table_name,
                                    'keys' => array('nonce_table',
                                                    'add_nonce',
                                                    'get_nonce',
                                                    'remove_nonce')
                                    ),
                              array(
                                    'value' => $this->associations_table_name,
                                    'keys' => array('assoc_table',
                                                    'set_assoc',
                                                    'get_assoc',
                                                    'get_assocs',
                                                    'remove_assoc')
                                    ),
                              array(
                                    'value' => $this->settings_table_name,
                                    'keys' => array('settings_table',
                                                    'get_auth',
                                                    'create_auth')
                                    )
                              );

        foreach ($replacements as $item) {
            $value = $item['value'];
            $keys = $item['keys'];

            foreach ($keys as $k) {
                if (is_array($this->sql[$k])) {
                    foreach ($this->sql[$k] as $part_key => $part_value) {
                        $this->sql[$k][$part_key] = sprintf($part_value,
                                                            $value);
                    }
                } else {
                    $this->sql[$k] = sprintf($this->sql[$k], $value);
                }
            }
        }
    }

    function blobDecode($blob)
    {
        return $blob;
    }

    function blobEncode($str)
    {
        return $str;
    }

    function createTables()
    {
        $n = $this->create_nonce_table();
        $a = $this->create_assoc_table();
        $s = $this->create_settings_table();

        if ($n && $a && $s) {
            $this->connection->commit();
            return true;
        } else {
            $this->connection->rollback();
            return false;
        }
    }

    function create_nonce_table()
    {
        $r = $this->connection->query($this->sql['nonce_table']);
        return _resultToBool($r);
    }

    function create_assoc_table()
    {
        $r = $this->connection->query($this->sql['assoc_table']);
        return _resultToBool($r);
    }

    function create_settings_table()
    {
        $r = $this->connection->query($this->sql['settings_table']);
        return _resultToBool($r);
    }

    /**
     * @access private
     */
    function _get_auth()
    {
        return $this->connection->getOne($this->sql['get_auth']);
    }

    /**
     * @access private
     */
    function _create_auth($str)
    {
        return $this->connection->query($this->sql['create_auth'],
                                        array($str));
    }

    function getAuthKey()
    {
        $value = $this->_get_auth();
        if (!$value) {
            $auth_key = Auth_OpenID_randomString($this->AUTH_KEY_LEN);

            $auth_key_s = $this->blobEncode($auth_key);
            $this->_create_auth($auth_key_s);
        } else {
            $auth_key_s = $value;
            $auth_key = $this->blobDecode($auth_key_s);
        }

        $this->connection->commit();

        if (strlen($auth_key) != $this->AUTH_KEY_LEN) {
            $fmt = "Expected %d-byte string for auth key. Got key of length %d";
            trigger_error(sprintf($fmt, $this->AUTH_KEY_LEN, strlen($auth_key)),
                          E_USER_WARNING);
            return null;
        }

        return $auth_key;
    }

    /**
     * @access private
     */
    function _set_assoc($server_url, $handle, $secret, $issued,
                        $lifetime, $assoc_type)
    {
        return $this->connection->query($this->sql['set_assoc'],
                                        array(
                                              $server_url,
                                              $handle,
                                              $secret,
                                              $issued,
                                              $lifetime,
                                              $assoc_type));
    }

    function storeAssociation($server_url, $association)
    {
        if (_resultToBool($this->_set_assoc(
                                            $server_url,
                                            $association->handle,
                                            $this->blobEncode(
                                                  $association->secret),
                                            $association->issued,
                                            $association->lifetime,
                                            $association->assoc_type
                                            ))) {
            $this->connection->commit();
        } else {
            $this->connection->rollback();
        }
    }

    /**
     * @access private
     */
    function _get_assoc($server_url, $handle)
    {
        $result = $this->connection->getRow($this->sql['get_assoc'],
                                            array($server_url, $handle));
        if (PEAR::isError($result)) {
            return null;
        } else {
            return $result;
        }
    }

    /**
     * @access private
     */
    function _get_assocs($server_url)
    {
        return $this->connection->getAll($this->sql['get_assocs'],
                                         array($server_url));
    }

    function removeAssociation($server_url, $handle)
    {
        if (!$this->getAssociation($server_url, $handle)) {
            return false;
        }

        if (_resultToBool($this->connection->query(
                              $this->sql['remove_assoc'],
                              array($server_url, $handle)))) {
            $this->connection->commit();
        } else {
            $this->connection->rollback();
        }

        return true;
    }

    function getAssociation($server_url, $handle = null)
    {
        if ($handle !== null) {
            $assoc = $this->_get_assoc($server_url, $handle);

            $assocs = array();
            if ($assoc) {
                $assocs[] = $assoc;
            }
        } else {
            $assocs = $this->_get_assocs($server_url);
        }

        if (count($assocs) == 0) {
            return null;
        } else {
            $associations = array();
            foreach ($assocs as $assoc_row) {
                $assoc = new Auth_OpenID_Association($assoc_row['handle'],
                                                     $assoc_row['secret'],
                                                     $assoc_row['issued'],
                                                     $assoc_row['lifetime'],
                                                     $assoc_row['assoc_type']);

                $assoc->secret = $this->blobDecode($assoc->secret);

                if ($assoc->getExpiresIn() == 0) {
                    $this->removeAssociation($server_url, $assoc->handle);
                } else {
                    $associations[] = array($assoc->issued, $assoc);
                }
            }

            if ($associations) {
                $issued = array();
                $assocs = array();
                foreach ($associations as $key => $assoc) {
                    $issued[$key] = $assoc[0];
                    $assocs[$key] = $assoc[1];
                }

                array_multisort($issued, SORT_DESC, $assocs, SORT_DESC,
                                $associations);

                // return the most recently issued one.
                list($issued, $assoc) = $associations[0];
                return $assoc;
            } else {
                return null;
            }
        }
    }

    /**
     * @access private
     */
    function _add_nonce($nonce, $expires)
    {
        return _resultToBool($this->connection->query($this->sql['add_nonce'],
                                                     array($nonce, $expires)));
    }

    /**
     * @access private
     */
    function storeNonce($nonce)
    {
        if ($this->_add_nonce($nonce, time())) {
            $this->connection->commit();
        } else {
            $this->connection->rollback();
        }
    }

    /**
     * @access private
     */
    function _get_nonce($nonce)
    {
        $result = $this->connection->getRow($this->sql['get_nonce'],
                                            array($nonce));

        if (PEAR::isError($result)) {
            return null;
        } else {
            return $result;
        }
    }

    /**
     * @access private
     */
    function _remove_nonce($nonce)
    {
        $this->connection->query($this->sql['remove_nonce'],
                                 array($nonce));
    }

    function useNonce($nonce)
    {
        $row = $this->_get_nonce($nonce);

        if ($row !== null) {
            $nonce = $row['nonce'];
            $timestamp = $row['expires'];
            $nonce_age = time() - $timestamp;

            if ($nonce_age > $this->max_nonce_age) {
                $present = 0;
            } else {
                $present = 1;
            }

            $this->_remove_nonce($nonce);
        } else {
            $present = 0;
        }

        $this->connection->commit();

        return $present;
    }
}

/**
 * An SQL store that uses PostgreSQL as its backend.
 *
 * @package OpenID
 */
class Auth_OpenID_PostgreSQLStore extends Auth_OpenID_SQLStore {
    function setSQL()
    {
        $this->sql['nonce_table'] =
            "CREATE TABLE %s (nonce CHAR(8) UNIQUE PRIMARY KEY, ".
            "expires INTEGER)";

        $this->sql['assoc_table'] =
            "CREATE TABLE %s (server_url VARCHAR(2047), handle VARCHAR(255), ".
            "secret BYTEA, issued INTEGER, lifetime INTEGER, ".
            "assoc_type VARCHAR(64), PRIMARY KEY (server_url, handle), ".
            "CONSTRAINT secret_length_constraint CHECK ".
            "(LENGTH(secret) <= 128))";

        $this->sql['settings_table'] =
            "CREATE TABLE %s (setting VARCHAR(128) UNIQUE PRIMARY KEY, ".
            "value BYTEA, ".
            "CONSTRAINT value_length_constraint CHECK (LENGTH(value) <= 20))";

        $this->sql['create_auth'] =
            "INSERT INTO %s VALUES ('auth_key', '!')";

        $this->sql['get_auth'] =
            "SELECT value FROM %s WHERE setting = 'auth_key'";

        $this->sql['set_assoc'] =
            array(
                  'insert_assoc' => "INSERT INTO %s (server_url, handle, ".
                  "secret, issued, lifetime, assoc_type) VALUES ".
                  "(?, ?, '!', ?, ?, ?)",
                  'update_assoc' => "UPDATE %s SET secret = '!', issued = ?, ".
                  "lifetime = ?, assoc_type = ? WHERE server_url = ? AND ".
                  "handle = ?"
                  );

        $this->sql['get_assocs'] =
            "SELECT handle, secret, issued, lifetime, assoc_type FROM %s ".
            "WHERE server_url = ?";

        $this->sql['get_assoc'] =
            "SELECT handle, secret, issued, lifetime, assoc_type FROM %s ".
            "WHERE server_url = ? AND handle = ?";

        $this->sql['remove_assoc'] =
            "DELETE FROM %s WHERE server_url = ? AND handle = ?";

        $this->sql['add_nonce'] =
            array(
                  'insert_nonce' => "INSERT INTO %s (nonce, expires) VALUES ".
                  "(?, ?)",
                  'update_nonce' => "UPDATE %s SET expires = ? WHERE nonce = ?"
                  );

        $this->sql['get_nonce'] =
            "SELECT * FROM %s WHERE nonce = ?";

        $this->sql['remove_nonce'] =
            "DELETE FROM %s WHERE nonce = ?";
    }

    /**
     * @access private
     */
    function _set_assoc($server_url, $handle, $secret, $issued, $lifetime,
                        $assoc_type)
    {
        $result = $this->_get_assoc($server_url, $handle);
        if ($result) {
            // Update the table since this associations already exists.
            $this->connection->query($this->sql['set_assoc']['update_assoc'],
                                     array($secret, $issued, $lifetime,
                                           $assoc_type, $server_url, $handle));
        } else {
            // Insert a new record because this association wasn't
            // found.
            $this->connection->query($this->sql['set_assoc']['insert_assoc'],
                                     array($server_url, $handle, $secret,
                                           $issued, $lifetime, $assoc_type));
        }
    }

    /**
     * @access private
     */
    function _add_nonce($nonce, $expires)
    {
        if ($this->_get_nonce($nonce)) {
            return _resultToBool($this->connection->query(
                                      $this->sql['add_nonce']['update_nonce'],
                                      array($expires, $nonce)));
        } else {
            return _resultToBool($this->connection->query(
                                      $this->sql['add_nonce']['insert_nonce'],
                                      array($nonce, $expires)));
        }
    }

    function blobEncode($blob)
    {
        return _octify($blob);
    }

    function blobDecode($blob)
    {
        return _unoctify($blob);
    }
}

/**
 * An SQL store that uses SQLite as its backend.
 *
 * @package OpenID
 */
class Auth_OpenID_SQLiteStore extends Auth_OpenID_SQLStore {
    function setSQL()
    {
        $this->sql['nonce_table'] =
            "CREATE TABLE %s (nonce CHAR(8) UNIQUE PRIMARY KEY, ".
            "expires INTEGER)";

        $this->sql['assoc_table'] =
            "CREATE TABLE %s (server_url VARCHAR(2047), handle VARCHAR(255), ".
            "secret BLOB(128), issued INTEGER, lifetime INTEGER, ".
            "assoc_type VARCHAR(64), PRIMARY KEY (server_url, handle))";

        $this->sql['settings_table'] =
            "CREATE TABLE %s (setting VARCHAR(128) UNIQUE PRIMARY KEY, ".
            "value BLOB(20))";

        $this->sql['create_auth'] =
            "INSERT INTO %s VALUES ('auth_key', ?)";

        $this->sql['get_auth'] =
            "SELECT value FROM %s WHERE setting = 'auth_key'";

        $this->sql['set_assoc'] =
            "INSERT OR REPLACE INTO %s VALUES (?, ?, ?, ?, ?, ?)";

        $this->sql['get_assocs'] =
            "SELECT handle, secret, issued, lifetime, assoc_type FROM %s ".
            "WHERE server_url = ?";

        $this->sql['get_assoc'] =
            "SELECT handle, secret, issued, lifetime, assoc_type FROM %s ".
            "WHERE server_url = ? AND handle = ?";

        $this->sql['remove_assoc'] =
            "DELETE FROM %s WHERE server_url = ? AND handle = ?";

        $this->sql['add_nonce'] =
            "INSERT OR REPLACE INTO %s (nonce, expires) VALUES (?, ?)";

        $this->sql['get_nonce'] =
            "SELECT * FROM %s WHERE nonce = ?";

        $this->sql['remove_nonce'] =
            "DELETE FROM %s WHERE nonce = ?";
    }
}

/**
 * An SQL store that uses MySQL as its backend.
 *
 * @package OpenID
 */
class Auth_OpenID_MySQLStore extends Auth_OpenID_SQLStore {
    function setSQL()
    {
        $this->sql['nonce_table'] =
            "CREATE TABLE %s (nonce CHAR(8) UNIQUE PRIMARY KEY, ".
            "expires INTEGER) TYPE=InnoDB";

        $this->sql['assoc_table'] =
            "CREATE TABLE %s (server_url BLOB, handle VARCHAR(255), ".
            "secret BLOB, issued INTEGER, lifetime INTEGER, ".
            "assoc_type VARCHAR(64), PRIMARY KEY (server_url(255), handle)) ".
            "TYPE=InnoDB";

        $this->sql['settings_table'] =
            "CREATE TABLE %s (setting VARCHAR(128) UNIQUE PRIMARY KEY, ".
            "value BLOB) TYPE=InnoDB";

        $this->sql['create_auth'] =
            "INSERT INTO %s VALUES ('auth_key', !)";

        $this->sql['get_auth'] =
            "SELECT value FROM %s WHERE setting = 'auth_key'";

        $this->sql['set_assoc'] =
            "REPLACE INTO %s VALUES (?, ?, !, ?, ?, ?)";

        $this->sql['get_assocs'] =
            "SELECT handle, secret, issued, lifetime, assoc_type FROM %s ".
            "WHERE server_url = ?";

        $this->sql['get_assoc'] =
            "SELECT handle, secret, issued, lifetime, assoc_type FROM %s ".
            "WHERE server_url = ? AND handle = ?";

        $this->sql['remove_assoc'] =
            "DELETE FROM %s WHERE server_url = ? AND handle = ?";

        $this->sql['add_nonce'] =
            "REPLACE INTO %s (nonce, expires) VALUES (?, ?)";

        $this->sql['get_nonce'] =
            "SELECT * FROM %s WHERE nonce = ?";

        $this->sql['remove_nonce'] =
            "DELETE FROM %s WHERE nonce = ?";
    }

    function blobEncode($blob)
    {
        return "0x" . bin2hex($blob);
    }
}

?>
