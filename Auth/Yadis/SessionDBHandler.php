<?php

/**
 * Session handler.
 *
 * @package Yadis
 * @author Petr Soukup (structure and most of the code based on original JanRain SQLStore.php class)
 */

/**
 * Require the base class file.
 */
require_once "Auth/Yadis/Manager.php";

global $__Auth_OpenID_PEAR_AVAILABLE;
$__Auth_OpenID_PEAR_AVAILABLE = @include_once 'MDB2.php';


/**
 * Session handler that uses database as a session store.
 *
 * @package Yadis
 */
class Auth_Yadis_SessionDBHandler extends Auth_Yadis_PHPSession {

    function Auth_Yadis_SessionDBHandler($connection,
                                        $sessions_table = null) 
    {

        global $__Auth_OpenID_PEAR_AVAILABLE;
        
        // Check the connection object type to be sure it's a PEAR
        // database connection.
        if (!(is_object($connection) &&
              (is_subclass_of($connection, 'MDB2_Driver_Common') ||
               is_subclass_of($connection,
                              'auth_openid_databaseconnection')))) {
            trigger_error("Auth_Yadis_SessionDBHandler expected PEAR connection " .
                          "object (got ".get_class($connection).")",
                          E_USER_ERROR);
            return;
        }

        $this->connection = $connection;

        // Be sure to set the fetch mode so the results are keyed on
        // column name instead of column index.  This is a PEAR
        // constant, so only try to use it if PEAR is present.
        // Furthermore, load Extended module needed for executing parametrized
        // SQL statements.
        if ($__Auth_OpenID_PEAR_AVAILABLE) {
            $this->connection->setFetchMode(MDB2_FETCHMODE_ASSOC);
            $this->connection->loadModule('Extended');
        }        

        // Set sessions table name.
        $this->sessions_table_name = "oid_sessions";
        if ($sessions_table) {
            $this->sessions_table_name = $sessions_table;
        }
        
        // Create an empty SQL strings array.
        $this->sql = array();
        // Set proper SQL strings for specific database backend.
        $this->setSQL();
        
        // Verify that all required SQL statements have been set, and
        // raise an error if any expected SQL strings were either
        // absent or empty.
        list($missing, $empty) = $this->verifySQL();
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
        $this->fixSQL();
    }
    
    /**
     * Provides SQL statements for specific database backend. Hence, this 
     * method should be overridden by subclasses.  Method is called by the 
     * constructor to set values in $this->sql, which is an array keyed on 
     * sql name.
     */
    function setSQL()
    {
    }

    /**
     * Verifies that all required SQL statements have been set.
     */
    function verifySQL()
    {
        $missing = array();
        $empty = array();

        $required_sql_keys = array(
                                   'setKey',
                                   'getKey',
                                   'delKey',
                                   'getAll',
                                   'clean',
                                   'createTable',
                                   'resetTable'
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
     * Adds table names to SQL queries.
     */
    function fixSQL()
    {
        $tableName = $this->sessions_table_name;
        $keys = array(
                   'setKey',
                   'getKey',
                   'delKey',
                   'getAll',
                   'clean',
                   'createTable',
                   'resetTable'
            );

            foreach ($keys as $k) {
                if (is_array($this->sql[$k])) {
                    foreach ($this->sql[$k] as $part_key => $part_value) {
                        $this->sql[$k][$part_key] = sprintf($part_value,
                                                            $tableName);
                    }
                } else {
                    $this->sql[$k] = sprintf($this->sql[$k], $tableName);
                }
            }
    }

    /**
     * Creates table for storing session keys.
     */    
    function createSessionTable(){
        $result = $this->connection->exec($this->sql['createTable']);

        if ($this->isError($result)){
            return false;
        } else {
            return true;
        }
    }

    /**
     * Set a session key/value pair.
     *
     * @param string $name The name of the session key to add.
     * @param string $value The value to add to the session.
     */
    function set($name, $value)
    {
        // serialized flag is used to determine whether array is to be set 
        // as a value
        $serialized = 0;
        
        // if value is an array it must be serialized prior to store into the
        // database
        if (is_array($value)){
            $value = serialize($value);
            $serialized = 1;
        }

        // store the key/value pair into the database
        $result = $this->connection->extended->execParam($this->sql['setKey'],
                                        array('keyName' => $name,
                                              'keyValue' => $value,
                                              'timestamp' => time(),
                                              'serialized' => $serialized
                                            ),
                                        array('text','text','integer','text'));

        if ($this->isError($result)){
            return false;
        } else {
            return true;
        }
    }

    /**
     * Get a key's value from the session.
     *
     * @param string $name The name of the key to retrieve.
     * @param string $default The optional value to return if the key
     * is not found in the session.
     * @return string $result The key's value in the session or
     * $default if it isn't found.
     */
    function get($name, $default=null)
    {
        // retrieve the row corresponding to the key name from the database
        $result = $this->connection->extended->getRow($this->sql['getKey'], null,
                                 array($name));

        if ($this->isError($result)){
            return $default;
        } else {
            // if result is empty return default value
            if ($result == array()){
                return $default;
            } else {
                // fetch key value
                $value = $result['keyValue'];
                
                // based on serialized flag we determine whether we serialized
                // the value before storing 
                // if so we have to unserialize it again
                if ($result['serialized'] == 1){
                    $value = unserialize($value);
                }

                return $value;
            }
        }
    }

    /**
     * Remove a key/value pair from the session.
     *
     * @param string $name The name of the key to remove.
     */
    function del($name)
    {
        $result = $this->connection->extended->execParam($this->sql['delKey'],
                                 array($name));

        if ($this->isError($result)){
            return -1;
        } else {
            return $result;
        }
    }

    /**
     * Return the contents of the session in array form.
     */
    function contents()
    {
        $result = $this->connection->queryAll($this->sql['getAll']);

        if ($this->isError($result)) {
            return array();
        } else {
            $content = array();
            $index = 0;

            // content is expected to be returned as a parametrized array
            // so we have to convert it this way
            foreach ($result as $row) {
                $keyValue = $row['keyValue'];
                if ($row['serialized'] == 1){
                    $keyValue = unserialize($keyValue);
                }
                $content[$index] = array(0 => $row['keyName'], 1 => $keyValue);
                $index++;
            }
            return $content;
        }        
    }

    /**
     * Performs a DB sessions table cleanup (deletes obsolete keys) if necessary.
     *
     * @param integer $maxAge The time interval (in millis) after that a 
     * session value becomes obsolete.
     */
    function cleanObsoleteKeys($maxAge)
    {
        $this->connection->beginTransaction();

        $num = $this->connection->extended->execParam($this->sql['clean'],
                                 array(time() - $maxAge),
                                 array('integer'));

        if ($this->isError($num)){
            if ($this->connection->in_transaction) {
                $this->connection->rollback();
            }
            return -1;
        } else {
            if ($this->connection->in_transaction) {
                $this->connection->commit();
            }
            return $num;
        }
    }

    /**
     * Returns true if $value constitutes a database error; returns
     * false otherwise.
     */
    function isError($result)
    {
        return PEAR::isError($result);
    }
}
?>