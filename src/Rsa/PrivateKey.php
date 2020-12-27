<?php

namespace Spatie\Crypto\Rsa;

use Spatie\Crypto\Rsa\Exceptions\CouldNotDecryptData;
use Spatie\Crypto\Rsa\Exceptions\FileDoesNotExist;
use Spatie\Crypto\Rsa\Exceptions\InvalidPrivateKey;

class PrivateKey
{
    /** @var resource */
    protected $privateKey;

    public static function fromString(string $privateKeyString, string $password = null): self
    {
        return new static($privateKeyString, $password);
    }

    public static function fromFile(string $pathToPrivateKey, string $password = null): self
    {
        if (! file_exists($pathToPrivateKey)) {
            throw FileDoesNotExist::make($pathToPrivateKey);
        }

        $privateKeyString = file_get_contents($pathToPrivateKey);

        return new static($privateKeyString, $password);
    }

    public function __construct(string $privateKeyString, string $password = null)
    {
        $this->privateKey = openssl_pkey_get_private($privateKeyString, $password);

        if ($this->privateKey === false) {
            throw InvalidPrivateKey::make();
        }
    }

    public function encrypt(string $data, int $block_size = 200): string
    {
        $encrypted = '';
        $data = str_split($data, $block_size);
        foreach($data as $chunk) {
            $partial = '';
            $ok = openssl_private_encrypt($chunk, $partial, $this->privateKey, OPENSSL_PKCS1_PADDING);
            if($ok === false) {
                throw CouldNotEncryptData::make();
            }
            $encrypted .= $partial;
        }
        return $encrypted;
    }

    public function canDecrypt(string $data): bool
    {
        try {
            $this->decrypt($data);
        } catch (CouldNotDecryptData $exception) {
            return false;
        }

        return true;
    }

    public function decrypt(string $data, int $block_size = 256): string
    {
        $decrypted = '';
        $data = str_split($data, $block_size);
        foreach($data as $chunk) {
            $partial = '';
            $ok = openssl_private_decrypt($chunk, $partial, $this->privateKey, OPENSSL_PKCS1_OAEP_PADDING);
            if($ok === false) {
                throw CouldNotDecryptData::make();
            }
            $decrypted .= $partial;
        }

        if (is_null($decrypted)) {
            throw CouldNotDecryptData::make();
        }

        return $decrypted;
    }

    public function details(): array
    {
        return openssl_pkey_get_details($this->privateKey);
    }

    public function sign(string $data): string
    {
        openssl_sign($data, $signature, $this->privateKey, OPENSSL_ALGO_SHA256);

        return base64_encode($signature);
    }
}
