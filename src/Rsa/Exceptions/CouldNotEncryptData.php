<?php

namespace Spatie\Crypto\Rsa\Exceptions;

use Exception;

class CouldNotEncryptData extends Exception
{
    public static function make(): self
    {
        return new self("Could not encrypt the data.");
    }
}
