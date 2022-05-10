<?php declare(strict_types=1);
namespace ThreeEncr;

use JsonSerializable;
use \Exception;

class TokenCrypt implements JsonSerializable
{
    public const HEADER_V1 = '3ncr.org/1#';
    private $key;

    /**
     * TokenCrypt constructor.
     * @param $secret - secret for encryption
     * @param $salt - salt for encryption
     * @param int $iter - number of PBKDF2 iterations
     */
    public function __construct(string $secret, string $salt, int $iter=1000)
    {
        $this->key = hash_pbkdf2('sha3-256', $secret, $salt, $iter, 0, true);
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
