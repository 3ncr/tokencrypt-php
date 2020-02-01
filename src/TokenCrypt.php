<?php
namespace ThreeEncr;

use JsonSerializable;

class TokenCrypt implements JsonSerializable {

    public const HEADER_V1 = "3ncr.org/1#";
    private $key;

    public function __construct($part1, $part2, $iter) {
        $this->key = hash_pbkdf2('sha3-256', $part1, $part2, $iter, 0, true);
    }

    /**
     * @param $source - source plain text
     * @return string - encrypted string
     * @throws \Exception - rare case when PHP could not generate cryptographically secure random number
     */
    public function encrypt3ncr($source) {
        $iv = random_bytes(12);
        $tag = '';
        $enc = openssl_encrypt($source,
            'aes-256-gcm',
            $this->key,
            OPENSSL_RAW_DATA,
            $iv, $tag);


        $encAll = $iv.$enc.$tag;

        return self::HEADER_V1 . rtrim(base64_encode($encAll), '=');
    }

    private function decrypt($base64data) {
        $decdata = base64_decode($base64data);
        if (strlen($decdata) < 12+16) {
            return false;
        }
        $iv = substr($decdata, 0, 12);
        $data = substr($decdata, 12, -16);
        $tag = substr($decdata, -16);
        $decrypted = openssl_decrypt($data,
            'aes-256-gcm',
            $this->key,
            OPENSSL_RAW_DATA,
            $iv, $tag);
        return $decrypted;
    }

    public function decrypt3ncr($encrypted) {
        $header = substr($encrypted, 0, strlen(self::HEADER_V1));
        if ($header !== self::HEADER_V1) {
            return $encrypted;
        }

        $data = substr($encrypted, strlen(self::HEADER_V1));
        $decrypted = $this->decrypt($data);
        if ($decrypted === false) {
            return $encrypted;
        }
        return $decrypted;
    }

    // silly attempts to hide a variable in a dynamic language

    public function __debugInfo() {
        return [];
    }

    public function jsonSerialize() {
        return [];
    }

    public  function  __sleep() {
        return [];
    }

}