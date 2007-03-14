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

$path_extra = dirname(dirname(dirname(__FILE__)));
$path = ini_get('include_path');
$path = $path_extra . PATH_SEPARATOR . $path;
ini_set('include_path', $path);
require_once "Auth/OpenID.php";

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

$messages = array();

session_start();
init_session();

if (!check_session() ||
    isset($_GET['add_openid'])) {
    render_form();
} else {
    print generate_config(isset($_GET['download']));
}

/**
 * Functions.
 */

function check_url($url) {
    return (Auth_OpenID::normalizeUrl($url) !== null);
}

function build_url() {
    $port = (($_SERVER['SERVER_PORT'] == 80) ? null : $_SERVER['SERVER_PORT']);

    $parts = explode("/", $_SERVER['SERVER_PROTOCOL']);
    $scheme = strtolower($parts[0]);

    if ($port) {
        return sprintf("%s://%s:%s%s/server.php", $scheme, $_SERVER['SERVER_NAME'],
                       $port, dirname($_SERVER['PHP_SELF']));
    } else {
        return sprintf("%s://%s%s/server.php", $scheme, $_SERVER['SERVER_NAME'],
                       dirname($_SERVER['PHP_SELF']));
    }
}

function check_open_basedir($path) {
  if (ini_get('open_basedir')) {
    $parts = explode(PATH_SEPARATOR, ini_get('open_basedir'));

    $found = false;

    foreach ($parts as $p) {
      if (strpos($path, $p) === 0) {
        $found = true;
        break;
      }
    }

    return $found;
  } else {
    return true;
  }
}

function check_session() {

    global $messages;

    if ($_GET && isset($_GET['clear'])) {
        session_destroy();
        $_SESSION = array();
        init_session();
        return false;
    }

    $bad_path = false;

    if (isset($_GET['generate'])) {
        if (!$_SESSION['server_url']) {
            $messages[] = "Please enter a server URL.";
        }

        if (!$_SESSION['store_type']) {
            $messages[] = "No store type chosen.";
        } else {
            switch ($_SESSION['store_type']) {
            case "Filesystem":
                if (!$_SESSION['store_data']['fs_path']) {
                    $messages[] = "Please specify a filesystem store path.";
                } else {
                  if (!check_open_basedir($_SESSION['store_data']['fs_path'])) {
                    $messages[] = "The filesystem store path violates PHP's <code>open_basedir</code> setting.";
                    $bad_path = true;
                  }
                }
                break;

            case "SQLite":
                if (!$_SESSION['store_data']['sqlite_path']) {
                    $messages[] = "Please specify a SQLite database path.";
                } else {
                  if (!check_open_basedir($_SESSION['store_data']['sqlite_path'])) {
                    $messages[] = "The SQLite store path violates PHP's <code>open_basedir</code> setting.";
                    $bad_path = true;
                  }
                }
                break;

            default:
                if (!($_SESSION['store_data']['host'] &&
                      $_SESSION['store_data']['database'] &&
                      $_SESSION['store_data']['username'] &&
                      $_SESSION['store_data']['password'])) {
                    $messages[] = "Please specify database connection details.";
                }
            }
        }
    }

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
          $_SESSION['store_data']['password'])) &&
        !$bad_path) {

        return true;
    }

    return false;
}

function render_form() {

    global $store_types, $fields, $messages;

    $basedir_msg = "";

    if (ini_get('open_basedir')) {
        $basedir_msg = "</br><span class=\"notice\">Note: Due to the ".
            "<code>open_basedir</code> php.ini setting, be sure to ".
            "choose a path in one of the following directories:<ul><li>".
            implode("<li>",
                    explode(PATH_SEPARATOR, ini_get('open_basedir'))).
            "</ul></span>";
    }

    $sqlite_found = false;
    if (extension_loaded('sqlite') ||
        @dl('sqlite.' . PHP_SHLIB_SUFFIX)) {
      $sqlite_found = true;
    }

    $mysql_found = false;
    if (extension_loaded('mysql') ||
        @dl('mysql.' . PHP_SHLIB_SUFFIX)) {
      $mysql_found = true;
    }

    $pgsql_found = false;
    if (extension_loaded('pgsql') ||
        @dl('pgsql.' . PHP_SHLIB_SUFFIX)) {
      $pgsql_found = true;
    }

?>
<html>
  <head>
    <style type="text/css">
span.label {
 float: left;
 width: 2in;
}

span.notice {
 color: red;
 font-size: 80%;
}

div p {
    border-top: 1px solid #ccc;
    font-style: italic;
    padding-top: 0.5em;
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

div.errors {
 background: #faa;
 border: 1px solid red;
}

</style>
</head>
<body>

<h2>OpenID Example Server Configuration</h2>

<?
if ($messages) {
    print "<div class=\"errors\">";
    foreach ($messages as $m) {
        print "<div>$m</div>";
    }
    print "</div>";

}
?>

<p>
Your browser has been redirected to this page so you can configure the
server example.  This form will auto-generate an OpenID example server
configuration for use with the OpenID server example.
</p>

<form>
<div>

  <p>
  The server URL is the URL that points to the "server.php" file.  It
  looks like your server URL should be <code><? print build_url(); ?></code>.
  </p>

  <span class="label"><label for="i_server_url">Server URL:</label></span>
  <span>
    <input type="text" id="i_server_url" size="35" name="server_url"
     value="<? print $_SESSION['server_url'] ?>">
  </span>
</div>

<div>

  <p>
  If this package isn't installed in the PHP include path, the package's
  directory should be added.  For example, if the package is in
  <code>/home/me/PHP-OpenID/</code>, you should enter that directory here.
  </p>

  <span class="label">
    <label for="i_include_path">Include path (optional):</label>
  </span>
  <span>
    <input type="text" id="i_include_path" size="35" name="include_path"
     value="<? print $_SESSION['include_path'] ?>">
  </span>
</div>

<div>

  <p>
  The server needs to store OpenID information in a "store".  The
  following store types are available on your PHP installation:
  </p>

  <span class="label">Store method:</span>
  <div class="store_fields">

    <div>
      <input type="radio" name="store_type" value="Filesystem"
       id="i_filesystem"<? if ($_SESSION['store_type'] == 'Filesystem') { print " CHECKED"; } ?>>
      <label for="i_filesystem">Filesystem</label>
      <div>
        <label for="i_fs_path" class="field">Filesystem path:</label>
        <input type="text" name="fs_path" id="i_fs_path"
         value="<? print $_SESSION['store_data']['fs_path']; ?>">
        <? print $basedir_msg; ?>
      </div>
    </div>

<? if ($sqlite_found) { ?>
    <div>
      <input type="radio" name="store_type" value="SQLite"
       id="i_sqlite"<? if ($_SESSION['store_type'] == 'SQLite') { print " CHECKED"; } ?>>
      <label for="i_sqlite">SQLite</label>
      <div>
        <label for="i_sqlite_path" class="field">SQLite database path:</label>
        <input type="text" value="<? print $_SESSION['store_data']['sqlite_path']; ?>"
         name="sqlite_path" id="i_sqlite_path">
        <? print $basedir_msg; ?>
      </div>
    </div>
<? } ?>


<? if ($mysql_found || $pgsql_found) { ?>
    <div>

<? if ($mysql_found) { ?>
      <input type="radio" name="store_type" value="MySQL"
       id="i_mysql"<? if ($_SESSION['store_type'] == 'MySQL') { print " CHECKED"; } ?>>
      <label for="i_mysql">MySQL</label>
<? } ?>

<? if ($pgsql_found) { ?>
      <input type="radio" name="store_type" value="PostgreSQL"
       id="i_pgsql"<? if ($_SESSION['store_type'] == 'PostgreSQL') { print " CHECKED"; } ?>>
      <label for="i_pgsql">PostgreSQL</label>
<? } ?>

      <div>
        <label for="i_m_host" class="field">Host:</label>
        <input type="text" value="<? print $_SESSION['store_data']['host']; ?>" name="host" id="i_m_host">
      </div>
      <div>
        <label for="i_m_database" class="field">Database:</label>
        <input value="<? print $_SESSION['store_data']['database']; ?>" type="text" name="database" id="i_m_database">
      </div>
      <div>
        <label for="i_m_username" class="field">Username:</label>
        <input type="text" name="username" id="i_m_username" value="<? print $_SESSION['store_data']['username']; ?>">
      </div>
      <div>
        <label for="i_m_password" class="field">Password:</label>
        <input type="password" name="password" id="i_m_password" value="<? print $_SESSION['store_data']['password']; ?>">
      </div>
    </div>
<? } ?>
</div>
</div>
<div>

  <p>
  Your OpenID server will need to know what URLs it can authenticate.  Supply URLs and passwords here.
  </p>

  <span class="label">OpenID URLs to serve:</span>

  <div class="store_fields">
<?
if ($_SESSION['users']) {
    print "<div><table><tr><th>OpenID URL</th><th>Password Hash</th></tr>";
    foreach ($_SESSION['users'] as $url => $p) {
        print "<tr><td>".$url."</td><td>".$p."</td></tr>";
    }
    print "</table></div>";
}
?>
   <div>
        <span>Add an OpenID:</span>
    <div>
      <label for="i_add_user" class="field">OpenID URL:</label><input type="text" name="openid_url" id="i_add_user">
    </div>
    <div>
      <label for="i_p1" class="field">Password:</label><input type="password" name="p1" id="i_p1">
    </div>
    <div>
      <label for="i_p2" class="field">Password (confirm):</label><input type="password" name="p2" id="i_p2">
    </div>

    <input type="submit" name="add_openid" value="Add OpenID">
   </div>

  </div>
</div>

<div>

  <p>
  Your OpenID server can be configured to trust a set of sites by default.  Enter those here.
  </p>

  <span class="label">Trusted sites:</span>

  <div class="store_fields">
<?
if ($_SESSION['trust_roots']) {
    print "<div><table><tr><th>Trusted site URL</th></tr>";
    foreach ($_SESSION['trust_roots'] as $url) {
        print "<tr><td>".$url."</td></tr>";
    }
    print "</table></div>";
}
?>
   <div>
    <span>Add a trusted site:</span>
    <div>
      <label for="i_tr" class="field">Trusted site URL:</label><input type="text" name="trust_root" id="i_tr">
    </div>
   </div>

  </div>
</div>

<input type="submit" name="generate" value="Generate Configuration">
</form>
</body>
</html>
<?
}

function init_session() {

    global $messages;

    // Set a guess value for the server url.
    if (!array_key_exists('server_url', $_SESSION)) {
        $_SESSION['server_url'] = build_url();
    }

    foreach (array('server_url', 'include_path', 'store_type') as $key) {
        if (!isset($_SESSION[$key])) {
            $_SESSION[$key] = "";
        }
    }

    if (!isset($_SESSION['store_data'])) {
        $_SESSION['store_data'] = array();
    }

    if (!isset($_SESSION['users'])) {
        $_SESSION['users'] = array();
    }

    if (!isset($_SESSION['trust_roots'])) {
        $_SESSION['trust_roots'] = array();
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

    if ($_GET &&
        isset($_GET['add_openid']) &&
        isset($_GET['openid_url']) &&
        isset($_GET['p1']) &&
        isset($_GET['p2']) &&
        $_GET['p1'] == $_GET['p2'] &&
        $_GET['p1']) {

        if (check_url($_GET['openid_url'])) {
            $normalized = Auth_OpenID::normalizeUrl($_GET['openid_url']);
            $_SESSION['users'][$normalized] = sha1($_GET['p1']);
        } else {
            $messages[] = "Cannot add OpenID URL; '".$_GET['openid_url']."' doesn't look like a URL.";
        }

    } else if ($_GET &&
               isset($_GET['trust_root']) &&
               $_GET['trust_root']) {
        if (!in_array($_GET['trust_root'], $_SESSION['trust_roots'])) {
            $_SESSION['trust_roots'][] = $_GET['trust_root'];
        }
    } else if ($_GET &&
               isset($_GET['del_user'])) {
        unset($_SESSION['users'][$_GET['del_user']]);
    }
}

function generate_config($download = false) {

    if ($download) {
        // Emit headers to force browser download.
        header("Content-type: text/plain");
        header("Content-disposition: attachment; filename=config.php");
    } else {
?>
<html>
<body>

<h2>OpenID Example Server Configuration</h2>

<p>
Put the following text into <strong><? print dirname(__FILE__); print DIRECTORY_SEPARATOR; ?>config.php</strong>.
</p>

<p>
<a href="setup.php?clear=1">Back to form</a> (resets settings)
</p>

<p>
<a href="setup.php?download=1">Download this configuration</a>
</p>

<pre style="border: 1px solid gray; background: #eee; padding: 5px;">
<?
}
?>
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

        print "require_once \"Auth/OpenID/FileStore.php\";\n    ";
        print "return new Auth_OpenID_FileStore(\"".$_SESSION['store_data']['fs_path']."\");\n";
        break;

    case "SQLite":

        print "require_once \"Auth/OpenID/SQLiteStore.php\";\n    ";
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
$openid_users = array(<?
$i = 0;
foreach ($_SESSION['users'] as $url => $hash) {
    $i++;
    print "\n    '$url' => '$hash'";
    if ($i < count($_SESSION['users'])) {
        print ",";
    }
}
?>

);

/**
 * Trusted sites is an array of trust roots.
 *
 * Sites in this list will not have to be approved by the user in
 * order to be used. It is OK to leave this value as-is.
 *
 * In a more robust server, this should be a per-user setting.
 */
$trusted_sites = array(<?
$i = 0;
foreach ($_SESSION['trust_roots'] as $url) {
    $i++;
    print "\n    '$url'";
    if ($i < count($_SESSION['trust_roots'])) {
        print ",";
    }
}
?>

);
<?
    if (!$download) {
?>
</pre>
</body>
</html>
<?
      }
    } // end function generate_config ()
?>
