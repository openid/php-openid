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

function mkstemp($dir) {
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

class Net_OpenID_FileStore extends Net_OpenID_OpenIDStore {

}

?>