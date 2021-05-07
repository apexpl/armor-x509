<?php
declare(strict_types = 1);

namespace Apex\Armor\x509;

use Apex\Armor\Armor;
use Apex\Armor\x509\{DistinguishedName, KeyUtils};
use Apex\Armor\x509\Exceptions\{Armorx509KeyNotExistsException, Armorx509InvalidKeyPasswordException};
use Apex\Db\Interfaces\DbInterface;
use Apex\Container\Di;

/**
 * x509 key manager
 */
class KeyManager extends KeyUtils
{

    /**
     * Constructor
     */
    public function __construct(
        private Armor $armor
    ) { 
        $this->db = Di::get(DbInterface::class);
    }

    /**
     * Generate CA
     */
    public function generate(
        string $uuid, 
        DistinguishedName $dn, 
        string $password, 
        bool $self_sign = false, 
        bool $save_privkey = false
    ):array { 

        // Generate CSR
        $res = $this->genCSR($dn, $password, $self_sign);
        $import_privkey = $save_privkey === true ? $res['privkey'] : '';

        // Import CSR
        if ($self_sign === true) { 
            $this->import($uuid, $res['pubkey'], $res['crt'], $import_privkey, false);
        } else { 
            $this->import($uuid, $res['pubkey'], $res['csr'], $import_privkey, true);
        }

        // Return
        return $res;
    }

    /**
     * Import
     */
    public function import(string $uuid, string $public_key, string $crt, string $private_key = '', bool $is_pending_sign = true):void
    {

        // Add to db
        $this->db->insert('armor_keys', [
            'is_pending_sign' => $is_pending_sign, 
            'uuid' => $uuid, 
            'algo' => 'x509', 
            'public_key' => $public_key, 
            'private_key' => $private_key, 
            'certificate' => $crt
        ]);

    }

    /**
     * Sign CSR
     */
    public function sign(string $uuid, string $signer_uuid, string $password, string $private_key = ''):string
    {

        // Get private key
        if ($private_key == '') { 
            $privkey = $this->getPrivKey($signer_uuid, $password);
        } else { 
            $privkey = $this->openPrivKey($private_key, $password);
        }

        // Get certificates
        $csr = $this->getCert($uuid);
        $signer_crt = $this->getCert($signer_uuid);

        // Sign
    $crt = $this->signCSR($csr, $signer_crt, $privkey);

        // Update database
        $this->db->update('armor_keys', [
            'is_pending_sign' => false, 
            'certificate' => $crt
        ], "uuid = %s AND algo = 'x509'", $uuid);

        // Return
        return $crt;
    }

    /**
     * Get certificate
     */
    public function getCert(string $uuid):?string
    {

        // Get from db
        if (!$crt = $this->db->getField("SELECT certificate FROM armor_keys WHERE uuid = %s AND algo = 'x509'", $uuid)) { 
            throw new Armorx509KeyNotExistsException("x509 certificate does not exist for uuid, $uuid");
        }

        // Return
        return $crt;
    }

    /**
     * Get public key
     */
    public function getPubKey(string $uuid):\OpenSSLAsymmetricKey
    {

        // Get from database
        if (!$public_key = $this->db->getField("SELECT public_key FROM armor_keys WHERE uuid = %s AND algo = 'x509'", $uuid)) { 
            throw new Armorx509KeyNotExistsException("Public key does not exist for uuid, $uuid");
        }

        // Open pubkey
        if (!$pubkey = openssl_pkey_get_public($public_key)) { 
            throw new Armorx509KeyNotExistsException("No public key exists for uuid, $uuid");
        }

        // Return
        return $pubkey;
    }

    /**
     * Get private key
     */
    public function getPrivKey(string $uuid, string $password):\OpenSSLAsymmetricKey
    {

        // Get from database
        if (!$privkey = $this->db->getField("SELECT private_key FROM armor_keys WHERE uuid = %s AND algo = 'x509'", $uuid)) { 
            throw new Armorx509KeyNotExistsException("Private key does not exist for uuid, $uuid");
        }

        // Open and return
        return $this->openPrivKey($privkey, $password);
    }

    /** 
     * Open private key
     */
    public function openPrivKey(string $private_key, string $password):\OpenSSLAsymmetricKey
    {

        if (!$privkey = openssl_pkey_get_private($private_key, $password)) { 
            throw new Armorx509InvalidKeyPasswordException("Invalid password for private key.");
        }

        // Return
        return $privkey;
    }


    /**
     * Issue certificate
     */
    public function issueCertificate()
    {

        // Generate key
        $privkey = openssl_pkey_new([
            "private_key_bits" => 4096,
            "private_key_type" => OPENSSL_KEYTYPE_RSA
        ]);

        // Get CA certificate
        $crtdata = file_get_contents('./keys/ca.crt');
        $ca_x509 = openssl_x509_read($crtdata);

        // Get priv key
        $keydata = file_get_contents('./keys/ca.key');
        if (!$ca_privkey = openssl_pkey_get_private($keydata, 'white4882')) { 
            echo "No priv key\n"; exit;
        }

        // Generate CSR
        $csr = openssl_csr_new($dn, $privkey, array('digest_alg' => 'sha384'));
        $x509 = openssl_csr_sign($csr, $ca_x509, $ca_privkey, 0, ['digest_alg' => 'sha384']);

        // Export keys
        openssl_csr_export($csr, $csrout);
        openssl_x509_export($x509, $certout);
        openssl_pkey_export($privkey, $pkeyout, 'white4882');
        $pubkey = openssl_pkey_get_details($privkey);

        // Set response
        $res = [
            'csr' => $csrout, 
            'crt' => $certout, 
            'privkey' => $pkeyout, 
            'pubkey' => $pubkey['key']
        ];

        // Return
        return $res;
    }


}



