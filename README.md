# tokencrypt-php (3ncr.org)

[![Lint & Test](https://github.com/3ncr/tokencrypt-php/actions/workflows/lint-and-test.yml/badge.svg)](https://github.com/3ncr/tokencrypt-php/actions/workflows/lint-and-test.yml)
[![Latest Stable Version](https://poser.pugx.org/3ncr/tokencrypt-php/v/stable)](https://packagist.org/packages/3ncr/tokencrypt-php)
[![Total Downloads](https://poser.pugx.org/3ncr/tokencrypt-php/downloads)](https://packagist.org/packages/3ncr/tokencrypt-php)
[![License: MIT](https://poser.pugx.org/3ncr/tokencrypt-php/license)](https://packagist.org/packages/3ncr/tokencrypt-php)

[3ncr.org](https://3ncr.org/) is a standard for string encryption / decryption
(algorithms + storage format), originally intended for encrypting tokens in
configuration files but usable for any UTF-8 string. v1 uses AES-256-GCM for
authenticated encryption with a 12-byte random IV:

```
3ncr.org/1#<base64(iv[12] || ciphertext || tag[16])>
```

Encrypted values look like
`3ncr.org/1#pHRufQld0SajqjHx+FmLMcORfNQi1d674ziOPpG52hqW5+0zfJD91hjXsBsvULVtB017mEghGy3Ohj+GgQY5MQ`.

This is the PHP 8.1+ implementation.

## Install

```bash
composer require 3ncr/tokencrypt-php
```

Requires PHP 8.1+ with `ext-openssl`, `ext-json`, and `ext-sodium` (the last is
used for Argon2id key derivation).

## Usage

Pick a constructor based on the entropy of your secret — see the
[3ncr.org v1 KDF guidance](https://3ncr.org/1/#kdf) for the canonical
recommendation.

### Recommended: raw 32-byte key (high-entropy secrets)

If you already have a 32-byte AES-256 key (random key, API token hashed to 32
bytes via SHA3-256, etc.), skip the KDF and pass it directly.

```php
$key = random_bytes(32);                              // or: load from env / secret store
$tokenCrypt = \ThreeEncr\TokenCrypt::fromRawKey($key);
```

### Recommended: Argon2id (passwords / low-entropy secrets)

For passwords or passphrases, use `fromArgon2id`. It uses the parameters
recommended by the [3ncr.org v1 spec](https://3ncr.org/1/#kdf)
(`m=19456 KiB, t=2, p=1`). The salt must be exactly 16 bytes (libsodium's
`crypto_pwhash` requirement, which matches the spec's "at least 16 random
bytes" recommendation at its minimum length and is interoperable with the Go
and Node implementations when the same salt is used).

```php
$tokenCrypt = \ThreeEncr\TokenCrypt::fromArgon2id($password, $salt);
```

### Legacy: PBKDF2-SHA3 (existing data only)

The original `(secret, salt, iterations)` constructor is kept for backward
compatibility with data encrypted by earlier versions. It is deprecated —
prefer `fromRawKey` or `fromArgon2id` for new code.

```php
$tokenCrypt = new \ThreeEncr\TokenCrypt($secret, $salt, 1000);
```

`$secret` and `$salt` are inputs to PBKDF2-SHA3 (technically one is the key,
the other is the salt, but you need to store them both somewhere, preferably
in different places). `1000` is the number of PBKDF2 rounds.

### Encrypt / decrypt

After constructing an instance, use `encrypt3ncr` and `decrypt3ncr`:

```php
$token = '08019215-B205-4416-B2FB-132962F9952F'; // your secret you want to encrypt
$encryptedSecretToken = $tokenCrypt->encrypt3ncr($token);
// $encryptedSecretToken === '3ncr.org/1#pHRufQld0SajqjHx+FmLMcORfNQi1d674ziOPpG52hqW5+0zfJD91hjXsBsvULVtB017mEghGy3Ohj+GgQY5MQ'

// ... some time later in another context ...

$decryptedSecretToken = $tokenCrypt->decrypt3ncr($encryptedSecretToken);
// $decryptedSecretToken === '08019215-B205-4416-B2FB-132962F9952F'
```

`decrypt3ncr` returns the input unchanged when it does not start with the
`3ncr.org/1#` header, so it is safe to route every configuration value through
it regardless of whether it was encrypted.

For JSON config files you can decrypt all 3ncr-encoded values in one pass:

```php
$encConfig = json_decode(file_get_contents('config.json'), true);
$config = $tokenCrypt->decrypt3ncrArray($encConfig);
```

## License

MIT — see [LICENSE](LICENSE).
