<?php

/**
  * An MSSQL store.
 *
 * @package OpenID
 * @author Petr Soukup
 */

/**
 * Require the base class file.
 */
require_once "Auth/OpenID/SQLStore.php";

/**
 * An SQL store that uses MSSQL as its backend.
 *
 * @package OpenID
 */
class Auth_OpenID_MSSQLStore extends Auth_OpenID_SQLStore {

    function setSQL()
    {
        $this->sql['nonce_table'] =
            "CREATE TABLE %s (\n".
            "  server_url VARCHAR(645) NOT NULL,\n".
            "  timestamp INTEGER NOT NULL,\n".
            "  salt CHAR(40) NOT NULL,\n".
            "  PRIMARY KEY (server_url, timestamp, salt))";

        $this->sql['assoc_table'] =
            "CREATE TABLE %s (\n".
            "  server_url VARCHAR(645) NOT NULL,\n".
            "  handle VARCHAR(255) NOT NULL,\n".
            "  secret VARBINARY(255) NOT NULL,\n".
            "  issued INTEGER NOT NULL,\n".
            "  lifetime INTEGER NOT NULL,\n".
            "  assoc_type VARCHAR(64) NOT NULL,\n".
            "  PRIMARY KEY (server_url, handle))";

        $this->sql['set_assoc'] =
            "UPDATE %1\$s SET server_url=%%1\$s, handle=%%2\$s, \n".
            "  secret=%%3\$s, issued=%%4\$s, lifetime=\n".
            "  %%5\$s, assoc_type=%%6\$s WHERE (server_url=%%1\$s \n".
            "  AND handle=%%2\$s); \n".
            "  IF @@ROWCOUNT=0 INSERT INTO %1\$s VALUES \n".
            "  (%%1\$s, %%2\$s, %%3\$s, %%4\$s, \n".
            "  %%5\$s, %%6\$s);";

        $this->sql['get_assocs'] =
            "SELECT handle, secret, issued, lifetime, assoc_type FROM %s ".
            "WHERE server_url = ?";

        $this->sql['get_assoc'] =
            "SELECT handle, secret, issued, lifetime, assoc_type FROM %s ".
            "WHERE server_url = ? AND handle = ?";

        $this->sql['remove_assoc'] =
            "DELETE FROM %s WHERE server_url = ? AND handle = ?";

        $this->sql['add_nonce'] =
            "INSERT INTO %s (server_url, timestamp, salt) VALUES (?, ?, ?)";

        $this->sql['clean_nonce'] =
            "DELETE FROM %s WHERE timestamp < ?";

        $this->sql['clean_assoc'] =
            "DELETE FROM %s WHERE issued + lifetime < ?";
    }

    /**
     * @access private
     */
    function _set_assoc($server_url, $handle, $secret, $issued,
                        $lifetime, $assoc_type)
    {
//        IMPOSSIBLE TO USE BECAUSE OF BAD QUOTING OF BLOB
//        $res = $this->connection->extended->execParam($this->sql['set_assoc'],
//                                        array(
//                                              'server_url' => $server_url,
//                                              'handle' => $handle,
//                                              'secret' => $secret,
//                                              'issued' => $issued,
//                                              'lifetime' => $lifetime,
//                                              'assoc_type' => $assoc_type));
////                                        array('text','text','blob','integer','integer','text'));

        $stmt = sprintf($this->sql['set_assoc'],
                    $this->connection->quote($server_url, 'text'),
                    $this->connection->quote($handle, 'text'),
                    $this->connection->quote($secret, 'blob', false),
                    $this->connection->quote($issued, 'integer'),
                    $this->connection->quote($lifetime, 'integer'),
                    $this->connection->quote($assoc_type, 'text'));
        $res = $this->connection->exec($stmt);
    }
    

    // SQL AZURE necessary (UTF8 not supported - cannot convert string to blob on DB)
    function blobEncode($str)
    {
        return "0x" . bin2hex($str);
    }

    // SQL AZURE necessary (UTF8 not supported)
    function blobDecode($blob)
    {
        return (binary) $blob;
    }
}
?>