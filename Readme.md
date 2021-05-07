
# Armor - x.509 Extension

An extension for the Armor package to provide x.509 signature and verify functionality.  This extension is still rather rudimentary, and will be updated in the near future.

**NOTE:** Although the functionality is technically there, please do not store private keys in the database.  This package is intended to provide storage for public keys and certificates, not private keys.

## Installation

Install via Composer with:

> `composer require apex/armor-x509`


## Basic Usage

~~~php
use Apex\Armor\Armor;
use Apex\Armor\x509\{KeyManager, DistinguishedName, Signature};

// Init Armor
$armor = new Armor();

// Get DN
$dn = new DistinguishedName(
    country: 'CA', 
    province: 'Ontario', 
    locality: 'Toronto', 
    org_name: 'Company XYZ', 
    common_name: 'fqdn.domain.com', 
    email: 'me@domain.com
);

// Generate self-signed cert for uuid u:admin
$manager = new KeyManager($armor);
$res = $manager->generate('u:admin', $dn, 'adminpass12345', true);

// Generate cert for uuid, u:581 signed by u:admin
$user = $manager->generate('u:581', $dn, 'password12345');
$manager->sign('u:581', 'u:admin', 'adminpass12345', $res['privkey']);

// Sign hash
$signer = new Signature($armor);
$user_privkey = $manager->openPrivKey($user_res['privkey'], 'password12345');
$sig = $signer->sign('message_to_sign', $user_privkey);

// Verify signature
if (!$signer->verify('message_to_sign', $sig, 'u:581', 'u:admin')) { 
    echo  "Unable to verify\n";
} else { 
    echo "Verification successful\n":
}
~~~


## Support

If you have any questions, issues or feedback, please feel free to drop a note on the <a href="https://reddit.com/r/apexpl/">ApexPl Reddit sub</a> for a prompt and helpful response.


## Follow Apex

Loads of good things coming in the near future including new quality open source packages, more advanced articles / tutorials that go over down to earth useful topics, et al.  Stay informed by joining the <a href="https://apexpl.io/">mailing list</a> on our web site, or follow along on Twitter at <a href="https://twitter.com/mdizak1">@mdizak1</a>.



