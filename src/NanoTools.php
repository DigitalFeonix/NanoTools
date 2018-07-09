<?php

namespace DigitalFeonix;

use DigitalFeonix\NanoSalt\FieldElement;
use DigitalFeonix\NanoSalt\Blake2b;
use DigitalFeonix\NanoSalt\Ed25519;
use DigitalFeonix\NanoSalt\GeExtended;

class NanoTools
{
    /**
     * Generate a hex seed
     * @return string the seed in hex representation
     */
    public static function generate_seed()
    {
        // create 32 byte seed, returned as hex string
        return strtoupper(bin2hex(random_bytes(32)));
    }

    /**
     * Encode the public key parts for address
     * @param  string  $key_str    key in binary str representation
     * @param  integer [$len = 52] number of 5bit chunks
     * @return string  encoded string
     */
    private static function encode_key($key_str, $len = 52)
    {
        // the symbols for the encoding
        $enc_str = '13456789abcdefghijkmnopqrstuwxyz';

        $ret = '';

        for ($b = 0; $b < $len; $b++)
        {
            $bit_chunk = substr($key_str, $b * 5, 5);
            $index = base_convert($bit_chunk, 2, 10);
            $ret .= $enc_str[$index];
        }

        return $ret;
    }

    /**
     * Generate the private key and public address based
     * on seed and account index
     *
     * @param  string  $seed_str      seed in hex
     * @param  integer [$account = 0] account index
     * @return array   private key and public address
     */
    public static function generate_address($seed_str, $account = 0)
    {
        $b2b = new Blake2b();

        $seed = FieldElement::fromHex($seed_str);

        // GENERATE SECRET KEY FOR SEED + ACCOUNT
        $priv_key = new FieldElement(64);
        $ctx = $b2b->init(null, 32);
        $b2b->update($ctx, $seed, 32);
        $b2b->update($ctx, FieldElement::fromHex(sprintf('%08x', $account)), 4);
        $b2b->finish($ctx, $priv_key);

        // generate the readable string just in case we want it later
        $priv_key_str = strtoupper(bin2hex(substr($priv_key->toString(), 0, 32)));

        // GENERATE PUBLIC KEY FROM PRIVATE KEY
        $hash = new FieldElement(64);
        $ctx = $b2b->init();
        $b2b->update($ctx, $priv_key, 32);
        $b2b->finish($ctx, $hash);

        $hash[0]  &= 248;
        $hash[31] &= 127;
        $hash[31] |= 64;

        $ed = Ed25519::instance();
        $A = new GeExtended();
        $pub_key = new FieldElement(32);
        $ed->geScalarmultBase($A, $hash);
        $ed->GeExtendedtoBytes($pub_key, $A);

        $pub_key_str = strtoupper(bin2hex($pub_key->toString()));

        // GENERATE THE ADDRESS FROM THE PUBLIC KEY
        $pub_key_bin_str = '0000';
        for ($b = 0; $b < 32; $b++)
        {
            $pub_key_bin_str .= sprintf('%08b', hexdec(substr($pub_key_str, $b * 2, 2)));
        }

        // NOTE: encode this and it would be the efficent spot for vanity
        // address checking

        // hash the public key with 5-byte digest length as a checksum element
        $out = new FieldElement(64);

        $ctx = $b2b->init(null, 5);
        $b2b->update($ctx, $pub_key, 32);
        $b2b->finish($ctx, $out);

        $checksum_hex_str = bin2hex(strrev(substr($out->toString(),0,5)));
        $checksum_bin_str = '';
        for ($b = 0; $b < 5; $b++)
        {
            $checksum_bin_str .= sprintf('%08b', hexdec(substr($checksum_hex_str, $b * 2, 2)));
        }

        // NOW ENCODE THE PARTS AND MAKE AN ADDRESS
        $encoded_key  = self::encode_key($pub_key_bin_str);
        $checksum     = self::encode_key($checksum_bin_str, 8);
        $pub_address  = 'nano_'.$encoded_key.$checksum;

        // RETURN THE PERTINENT RESULTS
        return [
            'priv_key'  => $priv_key_str,
            'address'   => $pub_address
        ];
    }

}
