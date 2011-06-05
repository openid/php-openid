<?php

/**
 * Session handler.
 *
 * @package Yadis
 * @author Petr Soukup
 */

/**
 * Require the base class file.
 */
require_once "Auth/Yadis/SessionDBHandler.php";


/**
 * Session handler that uses database as a session store with MSSQL as a backend.
 *
 * @package Yadis
 */
class Auth_Yadis_MSSQLSessionHandler extends Auth_Yadis_SessionDBHandler {

    function setSQL() {
        $this->sql['setKey']=
                "UPDATE %1\$s SET keyValue=:keyValue, timestamp=:timestamp, serialized=:serialized \n".
                "WHERE keyName=:keyName; \n".
                "IF @@ROWCOUNT=0 INSERT INTO %1\$s VALUES \n".
                "(:keyName, :keyValue, :timestamp, :serialized);";

        $this->sql['getKey']=
                "SELECT keyValue, serialized FROM %s WHERE keyName = ?;";
        
        $this->sql['delKey']=
                "DELETE FROM %s WHERE keyName = ?;";

        $this->sql['getAll']=
                "SELECT keyName, keyValue, serialized FROM %s;";
        
        $this->sql['clean']=
                "DELETE FROM %s WHERE timestamp < ?;";

        $this->sql['createTable']=
                "IF NOT EXISTS(SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = '%1\$s') \n".
                "CREATE TABLE %1\$s (\n".
                "keyName VARCHAR(255) NOT NULL, \n".
                "keyValue VARCHAR(MAX), \n".
                "timestamp INTEGER NOT NULL, \n".
                "serialized BIT \n".
                "PRIMARY KEY (keyName));";

        $this->sql['resetTable']=
                "DELETE FROM %s;";
    }
    
}
?>