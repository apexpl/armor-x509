<?php
declare(strict_types = 1);

namespace Apex\Armor\x509;

use Apex\Armor\Armor;


/**
 * Key utils
 */
class KeyUtils
{

    /**
     * Constructor
     */
    public function __construct(
        private Armor $armor
    ) {

    }

    /**
     * Generate new private key and CSR
     */
    public function genCSR(DistinguishedName $dn, string $password, bool $self_sign = false):array
    {

        // Generate key
        $privkey = openssl_pkey_new([
            "digest_alg" => "sha512",
            "private_key_bits" => 4096,
            "private_key_type" => OPENSSL_KEYTYPE_RSA
        ]);

        // Generate CSR
        $csr = openssl_csr_new($dn->toArray(), $privkey, array('digest_alg' => 'sha384'));

        // Self sign, if needed
        $crt_out = '';
        if ($self_sign === true) { 
            $x509 = openssl_csr_sign($csr, null, $privkey, 0, ['digest_alg' => 'sha384']);
            openssl_x509_export($x509, $crt_out);
        }

        // Export keys
        openssl_csr_export($csr, $csr_out);
        openssl_pkey_export($privkey, $privkey_out, $password);
        $pubkey = openssl_pkey_get_details($privkey);

        // Return
        return [
            'csr' => $csr_out, 
            'crt' => $crt_out, 
            'privkey' => $privkey_out, 
            'pubkey' => $pubkey['key']
        ];

    }

    /**
     * Sign CSR
     */
    public function signCSR(string $csr, string $crt, \OpenSSLAsymmetricKey $privkey, int $expire_days = 0):string
    {

        // Load CRT
        $crt = openssl_x509_read($crt);

        // Sign CSR
        $x509 = openssl_csr_sign($csr, $crt, $privkey, $expire_days, ['digest_alg' => 'sha384']);

        // Return
        openssl_x509_export($x509, $crt_out);
        return $crt_out;
    }


}



