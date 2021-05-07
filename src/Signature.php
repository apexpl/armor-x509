<?php
declare(strict_types = 1);

namespace Apex\Armor\x509;

use Apex\Armor\ARmor;
use Apex\Armor\x509\KeyManager;
use Apex\Armor\x509\Exceptions\Armorx509KeyNotExistsException;
use Apex\Db\Interfaces\DbInterface;
use Apex\Container\Di;

/**
 * Signatures
 */
class Signature
{

    /**
     * Constructor
     */
    public function __construct(
        private Armor $armor
    ) { 
        $this->db = Di::get(DbInterface::class);
        $this->manager = Di::make(KeyManager::class);
    }

    /**
     * Sign
     */
    public function sign(string $data, \OpenSSLAsymmetricKey $privkey):string
    {

        // Sign
        openssl_sign($data, $signature, $privkey);
        openssl_free_key($privkey);

        // Return
        return base64_encode($signature);
    }

    /**
     * Verify
     */
    public function verify(string $data, string $signature, string $uuid, string $issuer_uuid):bool
    {

        // Verify signature
        $pubkey = $this->manager->getPubKey($uuid);
        $ok = openssl_verify($data, base64_decode($signature), $pubkey);
        if ($ok != 1) { 
            return false;
        }

        // Get certificate and issuer pubkey
        $crt = $this->manager->getCert($uuid);
        $crt = openssl_x509_read($crt);
        $issuer_pubkey = $this->manager->getPubKey($issuer_uuid);

        // Verify certificate
        $ok = openssl_x509_verify($crt, $issuer_pubkey);
        if ($ok != 1) { 
            return false;
        }

        // Return
        return true;
    }

}


