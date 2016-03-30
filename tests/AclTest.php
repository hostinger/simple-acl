<?php

use Acl\Acl;

class AclTest extends PHPUnit_Framework_TestCase
{
    public $config = __DIR__ . '/acl.json';

    public function testConfig()
    {
        $acl = new Acl($this->config);
        var_dump($acl->getResources());
        $acl->getRoles();
    }
}
