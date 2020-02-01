<?php

use PHPUnit\Framework\TestCase;
use ThreeEncr\TokenCrypt;

class TokenCryptTest extends TestCase {

    private $testVectors = [
        '3ncr.org/1#I09Dwt6q05ZrH8GQ0cp+g9Jm0hD0BmCwEdylCh8' => 'a',
        '3ncr.org/1#Y3/v2PY7kYQgveAn4AJ8zP+oOuysbs5btYLZ9vl8DLc' => 'test',
        '3ncr.org/1#pHRufQld0SajqjHx+FmLMcORfNQi1d674ziOPpG52hqW5+0zfJD91hjXsBsvULVtB017mEghGy3Ohj+GgQY5MQ' =>
        '08019215-B205-4416-B2FB-132962F9952F',
        '3ncr.org/1#EPw7S5+BG6hn/9Sjf6zoYUCdwlzweeB+ahBIabUD6NogAcevXszOGHz9Jzv4vQ' => 'перевірка'
    ];

    public function testBasic() {
        $t = new TokenCrypt('a', 'b', 1000);

        foreach ($this->testVectors as $k=>$v) {
            $this->assertEquals($v, $t->decrypt3ncr($k));
        }
    }

    public function testIdentity() {
        $t = new TokenCrypt('a', 'b', 1000);
        $srcs = array_values($this->testVectors);

        foreach ($srcs as $src) {
            $enc = $t->encrypt3ncr($src);
            $dec = $t->decrypt3ncr($enc);
            $this->assertEquals($src, $dec);
        }
    }

    public function testDecrypt3ncrArray() {
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
}