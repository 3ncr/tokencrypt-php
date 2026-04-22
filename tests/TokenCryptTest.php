<?php declare(strict_types=1);

namespace ThreeEncr\Tests;

use PHPUnit\Framework\TestCase;
use ThreeEncr\TokenCrypt;
use ThreeEncr\TokenCryptException;

class TokenCryptTest extends TestCase
{
    private $testVectors = [
        '3ncr.org/1#I09Dwt6q05ZrH8GQ0cp+g9Jm0hD0BmCwEdylCh8' => 'a',
        '3ncr.org/1#Y3/v2PY7kYQgveAn4AJ8zP+oOuysbs5btYLZ9vl8DLc' => 'test',
        '3ncr.org/1#pHRufQld0SajqjHx+FmLMcORfNQi1d674ziOPpG52hqW5+0zfJD91hjXsBsvULVtB017mEghGy3Ohj+GgQY5MQ' =>
        '08019215-B205-4416-B2FB-132962F9952F',
        '3ncr.org/1#EPw7S5+BG6hn/9Sjf6zoYUCdwlzweeB+ahBIabUD6NogAcevXszOGHz9Jzv4vQ' => 'перевірка'
    ];

    public function testBasic()
    {
        $t = new TokenCrypt('a', 'b', 1000);

        foreach ($this->testVectors as $k=>$v) {
            $this->assertEquals($v, $t->decrypt3ncr($k));
        }
    }


    public function testCreateWithSecretLine()
    {
        $t = TokenCrypt::createWithSecretLine('shaashlick-@@-maashliyck-@@-1');

        $this->assertEquals(
            'test',
            $t->decrypt3ncr('3ncr.org/1#vTHRT8wXugLe92KDzhdV97jHW7ZL2TDh7mQ6laEK9NI')
        );
    }

    public function testIdentity()
    {
        $t = new TokenCrypt('a', 'b', 1000);
        $srcs = array_values($this->testVectors);

        foreach ($srcs as $src) {
            $enc = $t->encrypt3ncr($src);
            $dec = $t->decrypt3ncr($enc);
            $this->assertEquals($src, $dec);
        }
    }

    public function testDecrypt3ncrArray()
    {
        $encs = array_keys($this->testVectors);

        $encTest = [
            'token1' => $encs[0],
            'nonString' => 42,
            'subarrays' => [ [ $encs[1], $encs[2] ], false, 'okay' ],
            'justString' => 'string',
        ];
        $decs = array_values($this->testVectors);

        $decTest = [
            'token1' => $decs[0],
            'nonString' => 42,
            'subarrays' => [ [ $decs[1], $decs[2] ], false, 'okay' ],
            'justString' => 'string',
        ];

        $t = new TokenCrypt('a', 'b', 1000);

        $decArray = $t->decrypt3ncrArray($encTest);
        $this->assertEquals($decTest, $decArray);
    }

    public function testDecryptFail()
    {
        $encs = array_keys($this->testVectors);
        $fail = substr($encs[0], 0, -1);
        $t = new TokenCrypt('a', 'b', 1000);
        $this->assertNull($t->decrypt3ncr($fail));
        $t = new TokenCrypt('a', 'c', 1000);
        $this->assertNull($t->decrypt3ncr($encs[0]));
    }

    public function testFromRawKeyDecryptsCanonicalVectors()
    {
        $rawKey = hash_pbkdf2('sha3-256', 'a', 'b', 1000, 0, true);
        $t = TokenCrypt::fromRawKey($rawKey);

        foreach ($this->testVectors as $k => $v) {
            $this->assertEquals($v, $t->decrypt3ncr($k));
        }
    }

    public function testFromRawKeyIdentity()
    {
        $rawKey = random_bytes(32);
        $t = TokenCrypt::fromRawKey($rawKey);

        foreach (array_values($this->testVectors) as $src) {
            $enc = $t->encrypt3ncr($src);
            $dec = $t->decrypt3ncr($enc);
            $this->assertEquals($src, $dec);
        }
    }

    public function testFromRawKeyInteropWithLegacyConstructor()
    {
        $legacy = new TokenCrypt('a', 'b', 1000);
        $rawKey = hash_pbkdf2('sha3-256', 'a', 'b', 1000, 0, true);
        $raw = TokenCrypt::fromRawKey($rawKey);

        foreach (array_values($this->testVectors) as $src) {
            $this->assertEquals($src, $raw->decrypt3ncr($legacy->encrypt3ncr($src)));
            $this->assertEquals($src, $legacy->decrypt3ncr($raw->encrypt3ncr($src)));
        }
    }

    public function testFromRawKeyRejectsShortKey()
    {
        $this->expectException(TokenCryptException::class);
        TokenCrypt::fromRawKey(str_repeat("\x00", 31));
    }

    public function testFromRawKeyRejectsLongKey()
    {
        $this->expectException(TokenCryptException::class);
        TokenCrypt::fromRawKey(str_repeat("\x00", 33));
    }

    public function testFromRawKeyRejectsEmptyKey()
    {
        $this->expectException(TokenCryptException::class);
        TokenCrypt::fromRawKey('');
    }
}
