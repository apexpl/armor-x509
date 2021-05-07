<?php
declare(strict_types = 1);

use Apex\Armor\Armor;
use Apex\Armor\Policy\ArmorPolicy;
use Apex\Armor\x509\{KeyManager, DistinguishedName, Signature};
use Apex\Armor\User\ArmorUser;
use Apex\Container\Di;
use Apex\Db\Interfaces\DbInterface;
use PHPUnit\Framework\TestCase;

/**
 * PGP Keys
 */
class x509_test extends TestCase
{

    /**
     * Test create
     */
    public function test_create()
    {

        // set policy
        $policy = new ArmorPolicy(
            verify_email: 'none', 
            verify_phone: 'none'
        );

        // Init
        $armor = new Armor(
            container_file: $_SERVER['test_container_file'], 
            policy: $policy
        );
        $armor->purge();
        $admin = $armor->createUser('u:admin', 'adminpass12345', 'admin', 'admin@apexpl.io');
        $user = $armor->createUser('u:test', 'password12345', 'test', 'test@apexpl.io', '14165551234');
        $this->assertEquals(ArmorUser::class, $user::class);

        // Get DN
        $dn = new DistinguishedName(
            country: 'CA', 
            province: 'Ontario', 
            locality: 'Toronto', 
            org_name: 'Company XYZ', 
            org_unit: 'Dev Team', 
            common_name: 'dev.domain.com', 
            email: 'dev@domain.com'
        );

        // Generate self-signed cert
        $manager = Di::make(KeyManager::class);
        $res = $manager->generate('u:admin', $dn, 'adminpass12345', true);
        $this->assertIsArray($res);
        $this->assertNotEmpty($res['crt']);

        // Generate user CSR
        $user_res = $manager->generate('u:test', $dn, 'password12345');
        $this->assertIsArray($user_res);
        $this->assertEmpty($user_res['crt']);

        // Sign crt
        $crt = $manager->sign('u:test', 'u:admin', 'adminpass12345', $res['privkey']);
        $this->assertIsString($crt);
        $this->assertNotEmpty($crt);

        // Sign message
        $signer = new Signature($armor);
        $user_privkey = $manager->openPrivKey($user_res['privkey'], 'password12345');
        $sig = $signer->sign('test 12345', $user_privkey);
        $this->assertIsString($sig);
        $this->assertNotEmpty($sig);

        // Verify sig
        $ok = $signer->verify('test 12345', $sig, 'u:test', 'u:admin');
        $this->assertTrue($ok);
    }

}


