<?php

/**
 * OpenID server configuration script.
 *
 * This script generates a config.php file needed by the server
 * example.
 *
 * @package OpenID.Examples
 * @author JanRain, Inc. <openid@janrain.com>
 * @copyright 2005 Janrain, Inc.
 * @license http://www.gnu.org/copyleft/lesser.html LGPL
 */

/**
 * Data.
 */

$store_types = array("Filesystem" => "Auth_OpenID_FileStore",
                     "MySQL" => "Auth_OpenID_MySQLStore",
                     "PostgreSQL" => "Auth_OpenID_PostgreSQLStore",
                     "SQLite" => "Auth_OpenID_SQLiteStore");

/**
 * Main.
 */

session_start();
init_session();

if (!check_session()) {
    render_form();
} else {
    print generate_config();
}

/**
 * Functions.
 */

function check_session() {

    if ($_SESSION['store_type'] &&
        $_SESSION['server_url'] &&
        (parse_url($_SESSION['server_url']) !== false) &&
        ((($_SESSION['store_type'] == 'Filesystem') &&
          $_SESSION['store_data']['fs_path']) ||
         (($_SESSION['store_type'] == 'SQLite') &&
          $_SESSION['store_data']['sqlite_path']) ||
         ($_SESSION['store_data']['host'] &&
          $_SESSION['store_data']['username'] &&
          $_SESSION['store_data']['database'] &&
          $_SESSION['store_data']['password']))) {
        return true;
    }

    return false;
}

function render_form() {

    global $store_types;
    global $fields;

    $basedir_msg = "";

    if (ini_get('open_basedir')) {
        $basedir_msg = "</br><font color='red'>Note: Due to the ".
            "<strong>open_basedir</strong> setting, be sure to ".
            "choose a path in:<ul><li>".
            implode("<li>",
                    explode(PATH_SEPARATOR, ini_get('open_basedir'))).
            "</ul></font>";
    }

?>
<html>
  <head>
    <style type="text/css">
span.label {
 float: left;
 width: 2in;
}

div {
 padding: 3px;
}

div.store_fields {
 margin-left: 2in;
 padding: default;
}

div.store_fields label.field {
 float: left;
 width: 1.75in;
}

div.store_fields > div {
 border: 1px solid gray;
 margin-bottom: 0.5em;
 background: #eee;
}

div.store_fields > div > div {
    margin-left: 0.4in;
}

</style>
</head>
<body>

<h2>OpenID Server Configuration</h2>

<p>
This form will auto-generate an OpenID server configuration
for use with the OpenID server example.
</p>

<form>
<div>
  <span class="label"><label for="i_server_url">Server URL:</label></span>
  <span><input type="text" id="i_server_url" size="35" name="server_url" value="<? print $_SESSION['server_url'] ?>"></span>
</div>
<div>
  <span class="label"><label for="i_include_path">Include path (optional):</label></span>
  <span><input type="text" id="i_include_path" size="35" name="include_path" value="<? print $_SESSION['include_path'] ?>"></span>
</div>
<div>
  <span class="label">Store method:</span>
  <div class="store_fields">

    <div>
      <input type="radio" name="store_type" value="Filesystem" id="i_filesystem"<? if ($_SESSION['store_type'] == 'Filesystem') { print " CHECKED"; } ?>> <label for="i_filesystem">Filesystem</label>
      <div>
        <label for="i_fs_path" class="field">Filesystem path:</label>
        <input type="text" name="fs_path" id="i_fs_path" value="<? print $_SESSION['store_data']['fs_path']; ?>">
        <? print $basedir_msg; ?>
      </div>
    </div>

    <div>
      <input type="radio" name="store_type" value="SQLite" id="i_sqlite"<? if ($_SESSION['store_type'] == 'SQLite') { print " CHECKED"; } ?>> <label for="i_sqlite">SQLite</label>
      <div>
        <label for="i_sqlite_path" class="field">SQLite database path:</label><input type="text" value="<? print $_SESSION['store_data']['sqlite_path']; ?>" name="sqlite_path" id="i_sqlite_path">
        <? print $basedir_msg; ?>
      </div>
    </div>

    <div>
      <input type="radio" name="store_type" value="MySQL" id="i_mysql"<? if ($_SESSION['store_type'] == 'MySQL') { print " CHECKED"; } ?>> <label for="i_mysql">MySQL</label>
      <input type="radio" name="store_type" value="PostgreSQL" id="i_pgsql"<? if ($_SESSION['store_type'] == 'PostgreSQL') { print " CHECKED"; } ?>> <label for="i_pgsql">PostgreSQL</label>

      <div>
        <label for="i_m_host" class="field">Host:</label><input type="text" value="<? print $_SESSION['store_data']['host']; ?>" name="host" id="i_m_host">
      </div>
      <div>
        <label for="i_m_database" class="field">Database:</label><input value="<? print $_SESSION['store_data']['database']; ?>" type="text" name="database" id="i_m_database">
      </div>
      <div>
        <label for="i_m_username" class="field">Username:</label><input type="text" name="username" id="i_m_username" value="<? print $_SESSION['store_data']['username']; ?>">
      </div>
      <div>
        <label for="i_m_password" class="field">Password:</label><input type="password" name="password" id="i_m_password" value="<? print $_SESSION['store_data']['password']; ?>">
      </div>
    </div>

  </div>
</div>

<input type="submit" value="Generate Configuration">
</form>
</body>
</html>
<?
}

function init_session() {
    foreach (array('server_url', 'include_path', 'store_type') as $key) {
        if (!isset($_SESSION[$key])) {
            $_SESSION[$key] = "";
        }
    }

    if (!isset($_SESSION['store_data'])) {
        $_SESSION['store_data'] = array();
    }

    foreach (array('server_url', 'include_path', 'store_type') as $field) {
        if (array_key_exists($field, $_GET)) {
            $_SESSION[$field] = $_GET[$field];
        }
    }

    foreach (array('username', 'password', 'database', 'host', 'fs_path', 'sqlite_path') as $field) {
        if (array_key_exists($field, $_GET)) {
            $_SESSION['store_data'][$field] = $_GET[$field];
        }
    }
}

function generate_config() {
?>
<html>
<body>

<h2>OpenID Server Configuration</h2>

<p>
Put this text into a config file called <strong>config.php</strong>
and put it in the server example directory alongside server.php.
</p>

<pre style="border: 1px solid gray; background: #eee; padding: 5px;">
/**
 * OpenID server example settings
 *
 * The variables in this file must be customized before you can use
 * the server.
 *
 * @package OpenID.Examples
 * @author JanRain, Inc. <openid@janrain.com>
 * @copyright 2005 Janrain, Inc.
 * @license http://www.gnu.org/copyleft/lesser.html LGPL
 */

<? if ($_SESSION['include_path']) { ?>
/**
 * Set any extra include paths needed to use the library
 */
set_include_path(get_include_path() . PATH_SEPARATOR . "<?
print $_SESSION['include_path'];
?>");

<? } ?>
/**
 * The URL for the server.
 *
 * This is the location of server.php. For example:
 *
 * $server_url = 'http://example.com/~user/server.php';
 *
 * This must be a full URL.
 */
$server_url = "<?
print $_SESSION['server_url'];
?>";

/**
 * Initialize an OpenID store
 *
 * @return object $store an instance of OpenID store (see the
 * documentation for how to create one)
 */
function getOpenIDStore()
{
    <?

    switch ($_SESSION['store_type']) {
    case "Filesystem":

        print "return new Auth_OpenID_FileStore(\"".$_SESSION['store_data']['fs_path']."\");\n";
        break;

    case "SQLite":

        print "return new Auth_OpenID_SQLiteStore(\"".$_SESSION['store_data']['sqlite_path']."\");\n";
        break;

    case "MySQL":

        ?>require_once 'Auth/OpenID/MySQLStore.php';
    require_once 'DB.php';

    $dsn = array(
                 'phptype'  => 'mysql',
                 'username' => '<? print $_SESSION['store_data']['username']; ?>',
                 'password' => '<? print $_SESSION['store_data']['password']; ?>',
                 'hostspec' => '<? print $_SESSION['store_data']['host']; ?>'
                 );

    $db =& DB::connect($dsn);

    if (PEAR::isError($db)) {
        return null;
    }

    $db->query("USE <? print $_SESSION['store_data']['database']; ?>");
        
    return new Auth_OpenID_MySQLStore($db);
<?
        break;

    case "PostgreSQL":

        ?>require_once 'Auth/OpenID/PostgreSQLStore.php';
    require_once 'DB.php';

    $dsn = array(
                 'phptype'  => 'pgsql',
                 'username' => '<? print $_SESSION['store_data']['username']; ?>',
                 'password' => '<? print $_SESSION['store_data']['password']; ?>',
                 'hostspec' => '<? print $_SESSION['store_data']['host']; ?>',
                 'database' => '<? print $_SESSION['store_data']['database']; ?>'
                 );

    $db =& DB::connect($dsn);

    if (PEAR::isError($db)) {
        return null;
    }

    return new Auth_OpenID_PostgreSQLStore($db);
<?
        break;
    }

    ?>
}

/**
 * Users who are allowed to log in to this OpenID server.
 *
 * This is an array from URL to password hash. The URL must include
 * the proper OpenID server information in order to work with this
 * server.
 *
 * This must be set for the server to be usable. If it is not set, no
 * users will be able to log in.
 *
 * Example:
 * $openid_users = array(
 *                    'http://joe.example.com/' => sha1('foo')
 *                      )
 */
$openid_users = array();

/**
 * Trusted sites is an array of trust roots.
 *
 * Sites in this list will not have to be approved by the user in
 * order to be used. It is OK to leave this value as-is.
 *
 * In a more robust server, this site should be a per-user setting.
 */
$trusted_sites = array();
</pre>
</body>
</html>
<?
    } // end function generate_config ()
?>