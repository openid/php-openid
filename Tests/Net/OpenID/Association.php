<?php

require_once('PHPUnit.php');
require_once('Net/OpenID/Association.php');

class Tests_Net_OpenID_Association extends PHPUnit_TestCase {
    function test_me() {
        $issued = time();
        $lifetime = 600;
        $assoc = new Net_OpenID_Association('handle', 'secret', $issued,
                                            $lifetime, 'HMAC-SHA1');
        $s = $assoc->serialize();
        $assoc2 = Net_OpenID_Association::deserialize('Net_OpenID_Association',
                                                      $s);
        if ($assoc2 === null) {
            $this->fail('deserialize returned null');
        } else {
            $this->assertTrue($assoc2->equal($assoc));
        }
    }
}

?>