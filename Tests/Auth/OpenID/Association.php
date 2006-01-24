<?php

/**
 * Tests for the Association implementation.
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

require_once 'PHPUnit.php';
require_once 'Auth/OpenID/Association.php';

class Tests_Auth_OpenID_Association extends PHPUnit_TestCase {
    function test_me()
    {
        $issued = time();
        $lifetime = 600;
        $assoc = new Auth_OpenID_Association('handle', 'secret', $issued,
                                            $lifetime, 'HMAC-SHA1');
        $s = $assoc->serialize();
        $assoc2 = Auth_OpenID_Association::deserialize(
            'Auth_OpenID_Association', $s);

        if ($assoc2 === null) {
            $this->fail('deserialize returned null');
        } else {
            $this->assertTrue($assoc2->equal($assoc));
        }
    }
}

?>
