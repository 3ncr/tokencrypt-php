# tokencrypt-php (3ncr.org)

3ncr.org is a standard for string encryption/decryption (algorithms + storage format). Originally it was intended for 
encryption tokens in configuration files.  

3ncr.org v1 uses modern cryptographic primitives (SHA3-256, AES-256-GCM) and is fairly simple: 
```    
    header + base64(iv + data + tag) 
```

Encrypted data looks like this `3ncr.org/1#pHRufQld0SajqjHx+FmLMcORfNQi1d674ziOPpG52hqW5+0zfJD91hjXsBsvULVtB017mEghGy3Ohj+GgQY5MQ`

This is a PHP 7.1+ implementation.

## Usage


```php
$tokenCrypt = new \ThreeEncr\TokenCrypt($secret, $salt, 1000);
```

`$secret` and `$salt` - are encryption keys (technically one of them is key, another is salt, but you need to store them both somewhere). 

You can store them any preferred places: environment variables, files, shared memory, 
drive from serial numbers or MAC. Be creative. 

`1000` - is a number of PBKDF2 rounds. 
The more is better and slower. 
If you are sure that your secrets are long and random, you can keep this value reasonable low.  

After you created the class instance, you can just use encrypt3ncr and decrypt3ncr methods (the accept and return strings):

```php
$token = '08019215-B205-4416-B2FB-132962F9952F'; // your secret API key 
$encryptedSecretToken = $tokenCrypt->encrypt3ncr($token);
// now $encryptedSecretToken === '3ncr.org/1#pHRufQld0SajqjHx+FmLMcORfNQi1d674ziOPpG52hqW5+0zfJD91hjXsBsvULVtB017mEghGy3Ohj+GgQY5MQ'

// ... some time laster in another context ...  

$decryptedSecretToken = $tokenCrypt->decrypt3ncr($encryptedSecretToken); 
// now $decryptedSecretToken === ''08019215-B205-4416-B2FB-132962F9952F';
```

Or you can read JSON-file and decrypt its values: 
```
$encConfig = json_decode(file_get_contents('config.json'), false); 
$config = $token->decrypt3ncrArray($encConfig);   
```
