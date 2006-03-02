<?php

/**
 * The Auth_OpenID_DatabaseConnection class, which is used to emulate
 * a PEAR database connection.
 *
 * @package OpenID
 * @author JanRain, Inc. <openid@janrain.com>
 * @copyright 2005 Janrain, Inc.
 * @license http://www.gnu.org/copyleft/lesser.html LGPL
 */

/**
 * An empty base class intended to emulate PEAR connection
 * functionality in applications that supply their own database
 * abstraction mechanisms.  See {@link Auth_OpenID_SQLStore} for more
 * information.  You should subclass this class if you need to create
 * an SQL store that needs to access its database using an
 * application's database abstraction layer instead of a PEAR database
 * connection.
 *
 * @package OpenID
 */
class Auth_OpenID_DatabaseConnection {
    function setFetchMode($mode)
    {
    }

    function autoCommit($mode)
    {
    }

    function query($sql)
    {
    }

    function begin()
    {
    }

    function commit()
    {
    }

    function rollback()
    {
    }

    function getOne($sql)
    {
    }

    function getRow($sql)
    {
    }

    function getAll($sql)
    {
    }
}

?>