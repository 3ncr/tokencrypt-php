# tokencrypt-php (3ncr.org)

[![Latest Stable Version](https://poser.pugx.org/3ncr/tokencrypt-php/v/stable)](https://packagist.org/packages/3ncr/tokencrypt-php) [![Total Downloads](https://poser.pugx.org/3ncr/tokencrypt-php/downloads)](https://packagist.org/packages/3ncr/tokencrypt-php) [![License](https://poser.pugx.org/3ncr/tokencrypt-php/license)](https://packagist.org/packages/3ncr/tokencrypt-php) ![Build Status](https://github.com/3ncr/tokencrypt-php/actions/workflows/lint-and-test.yml/badge.svg)


3ncr.org is a standard for string encryption/decryption (algorithms + storage format). Originally it was intended for 
encryption tokens in configuration files.  

3ncr.org v1 uses AES-256-GCM and is fairly simple: 
```    
    header + base64(iv + data + tag) 
```

Encrypted data looks like this `3ncr.org/1#pHRufQld0SajqjHx+FmLMcORfNQi1d674ziOPpG52hqW5+0zfJD91hjXsBsvULVtB017mEghGy3Ohj+GgQY5MQ`

This is a PHP 7.2+ implementation.

## Usage

### Recommended: raw 32-byte key

Pass a 32-byte binary string containing an AES-256 key. Derive it however you prefer —
for passwords use Argon2id; for high-entropy inputs (random keys, API tokens) a single
SHA3-256 hash is sufficient.

```php
$key = random_bytes(32);                              // or: load from env / secret store
$tokenCrypt = \ThreeEncr\TokenCrypt::fromRawKey($key);
```

### Legacy: PBKDF2-SHA3 constructor

The original `(secret, salt, iterations)` constructor is kept for backward compatibility
with data encrypted by earlier versions. It is deprecated — prefer `fromRawKey()` above
for new code.

```php
$tokenCrypt = new \ThreeEncr\TokenCrypt($secret, $salt, 1000);
```

`$secret` and `$salt` are inputs to PBKDF2-SHA3 (one of them is key, the other is salt,
but you need to store them both somewhere, preferably in different places).

You can store them in any preferred places: environment variables, files, shared memory,
derived from serial numbers or MAC. Be creative.

`1000` is the number of PBKDF2 rounds. Higher is slower and more resistant to
brute-force. If you are sure your secrets have 256 bits of entropy and are fairly random,
you can use `1` (essentially a single HMAC SHA3 hash).

### Encrypt / decrypt

After you created the class instance, you can use `encrypt3ncr` and `decrypt3ncr` methods
(they accept and return strings):

```php
$token = '08019215-B205-4416-B2FB-132962F9952F'; // your secret you want to encrypt 
$encryptedSecretToken = $tokenCrypt->encrypt3ncr($token);
// now $encryptedSecretToken === '3ncr.org/1#pHRufQld0SajqjHx+FmLMcORfNQi1d674ziOPpG52hqW5+0zfJD91hjXsBsvULVtB017mEghGy3Ohj+GgQY5MQ'

// ... some time later in another context ...  

$decryptedSecretToken = $tokenCrypt->decrypt3ncr($encryptedSecretToken); 
// now $decryptedSecretToken === ''08019215-B205-4416-B2FB-132962F9952F';
```

Or you can read JSON-file and decrypt its values: 
```
$encConfig = json_decode(file_get_contents('config.json'), false); 
$config = $token->decrypt3ncrArray($encConfig);   
```
