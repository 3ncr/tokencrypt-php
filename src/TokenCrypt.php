<?php declare(strict_types=1);
namespace ThreeEncr;

use JsonSerializable;
use \Exception;

class TokenCrypt implements JsonSerializable
{
    public const HEADER_V1 = '3ncr.org/1#';
    public const KEY_SIZE = 32;

    // 3ncr.org recommended Argon2id parameters for interoperability
    // (see https://3ncr.org/1/ - Key Derivation section).
    public const ARGON2ID_MEMORY_KIB = 19456;
    public const ARGON2ID_TIME_COST = 2;
    public const ARGON2ID_SALT_BYTES = 16;

    private $key;

    /**
     * TokenCrypt constructor (legacy PBKDF2-SHA3 KDF).
     *
     * @param $secret - secret for encryption
     * @param $salt - salt for encryption
     * @param int $iter - number of PBKDF2 iterations
     * @deprecated PBKDF2-SHA3 is the legacy KDF. Derive your own 32-byte key and
     *             pass it to self::fromRawKey() (Argon2id for passwords, SHA3-256
     *             for high-entropy inputs — see 3ncr.org spec).
     */
    public function __construct(string $secret, string $salt, int $iter=1000)
    {
        $this->key = hash_pbkdf2('sha3-256', $secret, $salt, $iter, 0, true);
    }

    /**
     * Creates a TokenCrypt instance from a raw 32-byte AES-256 key.
     *
     * Derive the key however you prefer — Argon2id for passwords, a single
     * SHA3-256 hash for high-entropy inputs (random keys, API tokens). See the
     * 3ncr.org spec for recommended parameters.
     *
     * @param string $key - raw 32-byte key (binary string)
     * @throws TokenCryptException if $key is not exactly KEY_SIZE bytes
     */
    public static function fromRawKey(string $key): self
    {
        $len = strlen($key);
        if ($len !== self::KEY_SIZE) {
            throw new TokenCryptException(sprintf(
                'Raw key must be exactly %d bytes, got %d',
                self::KEY_SIZE,
                $len
            ));
        }
        $instance = (new \ReflectionClass(self::class))->newInstanceWithoutConstructor();
        $instance->key = $key;
        return $instance;
    }

    /**
     * Creates a TokenCrypt instance using the 3ncr.org recommended Argon2id
     * KDF for low-entropy secrets (passwords, passphrases). Parameters follow
     * the spec (https://3ncr.org/1/ - Key Derivation): memory 19456 KiB,
     * iterations 2, parallelism 1, output 32 bytes.
     *
     * Uses libsodium's crypto_pwhash, which requires a salt of exactly 16
     * bytes. This matches the spec's "at least 16 random bytes" recommendation
     * at its minimum length and is interoperable with Argon2id keys derived by
     * the Go and Node implementations when the same 16-byte salt is used.
     *
     * @param string $secret - secret / passphrase to derive the key from
     * @param string $salt - salt, must be exactly 16 bytes
     * @throws TokenCryptException if ext-sodium is missing or $salt length is wrong
     */
    public static function fromArgon2id(string $secret, string $salt): self
    {
        if (!function_exists('sodium_crypto_pwhash')) {
            throw new TokenCryptException('ext-sodium is required for Argon2id key derivation');
        }
        if (strlen($salt) !== self::ARGON2ID_SALT_BYTES) {
            throw new TokenCryptException(sprintf(
                'Argon2id salt must be exactly %d bytes, got %d',
                self::ARGON2ID_SALT_BYTES,
                strlen($salt)
            ));
        }
        $key = sodium_crypto_pwhash(
            self::KEY_SIZE,
            $secret,
            $salt,
            self::ARGON2ID_TIME_COST,
            self::ARGON2ID_MEMORY_KIB * 1024,
            SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
        );
        return self::fromRawKey($key);
    }

    /**
     * Creates object from a single string. Secret line is a crude 'format' for storing secret, salt and number
     * of iterations in the same string (separated by -@@-). Secret and salt should not be empty.
     *
     * @param string $line
     * @return ?TokenCrypt
     * @throws TokenCryptException
     */
    public static function createWithSecretLine(string $line): ?TokenCrypt
    {
        $parts = explode('-@@-', $line, 3);
        if (count($parts) != 3) {
            return null;
        }
        if ((strlen($parts[0]) < 1)||(strlen($parts[1]) < 1)) {
            throw new TokenCryptException('Malformed secret-line - part1 or part2 empty');
        }
        $iter = intval($parts[2]);
        if ($iter == 0) {
            throw new TokenCryptException('Malformed secret-line - bad iterations number');
        }
        return new TokenCrypt($parts[0], $parts[1], $iter);
    }

    /**
     * @param $source - source plain text
     * @return string - encrypted string
     * @throws Exception - rare case when PHP could not generate cryptographically secure random number
     */
    public function encrypt3ncr(string $source): string
    {
        $iv = random_bytes(12);
        $tag = '';
        $enc = openssl_encrypt(
            $source,
            'aes-256-gcm',
            $this->key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        $encAll = $iv.$enc.$tag;

        return self::HEADER_V1 . rtrim(base64_encode($encAll), '=');
    }

    private function decrypt(string $base64data): ?string
    {
        $decdata = base64_decode($base64data);
        if (strlen($decdata) < 12+16) {
            return null;
        }
        $iv = substr($decdata, 0, 12);
        $data = substr($decdata, 12, -16);
        $tag = substr($decdata, -16);
        $decrypted = openssl_decrypt(
            $data,
            'aes-256-gcm',
            $this->key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );
        if ($decrypted === false) {
            $decrypted = null;
        }

        return $decrypted;
    }

    /**
     * @param $encrypted - encrypted 3ncr-string
     * @return ?string false if failed, input argument if it is not 3ncr-string or decrypted string
     */
    public function decrypt3ncr(string $encrypted): ?string
    {
        $header = substr($encrypted, 0, strlen(self::HEADER_V1));
        if ($header !== self::HEADER_V1) {
            return $encrypted;
        }

        $data = substr($encrypted, strlen(self::HEADER_V1));
        $decrypted = $this->decrypt($data);
        if ($decrypted === null) {
            return null;
        }
        return $decrypted;
    }


    /**
     * @param $dict - associative array
     * @return array - copy of the array, where all 3ncr-strings in array values were decrypted
     */
    public function decrypt3ncrArray(array $dict): array
    {
        $result = [];
        foreach ($dict as $k=>$v) {
            if (is_string($v)) {
                $result[$k] = $this->decrypt3ncr($v);
            } elseif (is_array($v)) {
                $result[$k] = $this->decrypt3ncrArray($v);
            } else {
                $result[$k] = $v;
            }
        }
        return $result;
    }

    // silly attempts to hide a variable in a dynamic language

    public function __debugInfo(): array
    {
        return [];
    }

    /**
     * @return mixed
     */
    #[\ReturnTypeWillChange]
    public function jsonSerialize()
    {
        return [];
    }

    public function __sleep(): array
    {
        return [];
    }
}
