<?php

/**
 * This file supplies a Memcached store backend for OpenID servers and
 * consumers.
 *
 * PHP versions 4 and 5
 *
 * LICENSE: See the COPYING file included in this distribution.
 *
 * @package OpenID
 * @author JanRain, Inc. <openid@janrain.com>
 * @copyright 2005 Janrain, Inc.
 * @license http://www.gnu.org/copyleft/lesser.html LGPL
 *
 */

require('Interface.php');

function Net_OpenID_mkstemp($dir) {
    foreach (range(0, 4) as $i) {
        $name = tempnam($dir, "php_openid_filestore_");
        $fd = fopen($name, 'x+', 0600);

        if ($fd === false) {
            return false;
        } else {
            return array($fd, $name);
        }
    }
    return false;
}

$letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
$digits = "0123456789";

$_Net_OpenID_filename_allowed = $letters . $digits . ".";

function _isFilenameSafe($char) {
    global $_Net_OpenID_filename_allowed;
    return (strpos($_Net_OpenID_filename_allowed, $hcar) !== false);
}

function _safe64($str) {
    $h64 = Net_OpenID_toBase64(Net_OpenID_CryptUtil::sha1($str));
    $h64 = str_replace('+', '_', $h64);
    $h64 = str_replace('/', '.', $h64);
    $h64 = str_replace('=', '', $h64);
    return $h64;
}

function _filenameEscape($str) {
    $filename_chunks = array();
    for ($i = 0; $i < strlen($str); $i++) {
        $c = $str[$i];
        if (_isFilenameSafe($c)) {
            $filename_chunks[] = $c;
        } else {
            $filename_chunks[] = sprintf("_%02X", ord(c));
        }
    }
    return implode("", $filename_chunks);
}

/**
 * Attempt to remove a file, returning whether the file existed at the
 * time of the call.
 *
 * @return bool $result True if the file was present, false if not.
 */
function _removeIfPresent($filename) {
    return @unlink($filename);
}

/**
 * Create dir_name as a directory if it does not exist. If it exists,
 * make sure that it is, in fact, a directory.  Returns true if the
 * operation succeeded; false if not.
 */
function _ensureDir($dir_name) {
    if (mkdir($dir_name) || is_dir($dir_name)) {
        return true;
    } else {
        return false;
    }
}

/**
 * This is a filesystem-based store for OpenID associations and
 * nonces.  This store should be safe for use in concurrent systems on
 * both windows and unix (excluding NFS filesystems).  There are a
 * couple race conditions in the system, but those failure cases have
 * been set up in such a way that the worst-case behavior is someone
 * having to try to log in a second time.
 *
 * Most of the methods of this class are implementation details.
 * People wishing to just use this store need only pay attention to
 * the constructor.
 *
 * Methods of this object can raise OSError if unexpected filesystem
 * conditions, such as bad permissions or missing directories, occur.
*/
class Net_OpenID_FileStore extends Net_OpenID_OpenIDStore {

    /**
     * Initializes a new FileOpenIDStore.  This initializes the nonce
     * and association directories, which are subdirectories of the
     * directory passed in.
     *
     * @param string $directory This is the directory to put the store
     * directories in.
     */
    function Net_OpenID_FileStore($directory) {
    }

    /**
     * Make sure that the directories in which we store our data
     * exist.
     */
    function _setup() {
    }

    /**
     * Create a temporary file on the same filesystem as
     * self.auth_key_name and self.association_dir.
     *
     * The temporary directory should not be cleaned if there are any
     * processes using the store. If there is no active process using
     * the store, it is safe to remove all of the files in the
     * temporary directory.
     *
     * @return array ($file, 
     */
    function _mktemp() {
    }

    /**
     * Read the auth key from the auth key file. Will return None if
     * there is currently no key.
     *
     * @return mixed
     */
    function readAuthKey() {
    }

    /**
     * Generate a new random auth key and safely store it in the
     * location specified by self.auth_key_name.
     *
     * @return string $key
     */
    function createAuthKey() {
    }

    /**
     * Retrieve the auth key from the file specified by
     * self.auth_key_name, creating it if it does not exist.
     *
     * @return string $key
     */
    function getAuthKey() {
    }

    /**
     * Create a unique filename for a given server url and
     * handle. This implementation does not assume anything about the
     * format of the handle. The filename that is returned will
     * contain the domain name from the server URL for ease of human
     * inspection of the data directory.
     *
     * @return string $filename
     */
    function getAssociationFilename($server_url, $handle) {
    }

    /**
     * Store an association in the association directory.
     */
    function storeAssociation($server_url, $association) {
    }

    /**
     * Retrieve an association. If no handle is specified, return the
     * association with the latest expiration.
     *
     * @return mixed $association
     */
    function getAssociation($server_url, $handle = null) {
    }

    function _getAssociation($filename) {
    }

    /**
     * Remove an association if it exists. Do nothing if it does not.
     *
     * @return bool $success
     */
    function removeAssociation($server_url, $handle) {
    }

    /**
     * Mark this nonce as present.
     */
    function storeNonce($nonce) {
    }

    /**
     * Return whether this nonce is present. As a side effect, mark it
     * as no longer present.
     *
     * @return bool $present
     */
    function useNonce($nonce) {
    }

    /**
     * Remove expired entries from the database. This is potentially
     * expensive, so only run when it is acceptable to take time.
     */
    function clean() {
    }
}

?>