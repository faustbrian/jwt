<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests;

use Cline\JWT\Contracts\Signer\KeyInterface;
use Cline\JWT\Signer\Key\InMemory;
use PHPUnit\Framework\Attributes\BeforeClass;

/**
 * @author Brian Faust <brian@cline.sh>
 */
trait Keys
{
    /** @var array<string, KeyInterface> */
    protected static array $rsaKeys;

    /** @var array<string, KeyInterface> */
    protected static array $ecdsaKeys;

    /** @var array<string, KeyInterface> */
    protected static array $edDsaKeys;

    #[BeforeClass()]
    public static function createRsaKeys(): void
    {
        if (isset(static::$rsaKeys)) {
            return;
        }

        static::$rsaKeys = [
            'private' => InMemory::file(__DIR__.'/_keys/rsa/private.key'),
            'public' => InMemory::file(__DIR__.'/_keys/rsa/public.key'),
            'encrypted-private' => InMemory::file(__DIR__.'/_keys/rsa/encrypted-private.key', 'testing'),
            'encrypted-public' => InMemory::file(__DIR__.'/_keys/rsa/encrypted-public.key'),
            'private_short' => InMemory::file(__DIR__.'/_keys/rsa/private_512.key'),
            'public_short' => InMemory::file(__DIR__.'/_keys/rsa/public_512.key'),
        ];
    }

    #[BeforeClass()]
    public static function createEcdsaKeys(): void
    {
        if (isset(static::$ecdsaKeys)) {
            return;
        }

        static::$ecdsaKeys = [
            'private' => InMemory::file(__DIR__.'/_keys/ecdsa/private.key'),
            'private-params' => InMemory::file(__DIR__.'/_keys/ecdsa/private2.key'),
            'public1' => InMemory::file(__DIR__.'/_keys/ecdsa/public1.key'),
            'public2' => InMemory::file(__DIR__.'/_keys/ecdsa/public2.key'),
            'public-params' => InMemory::file(__DIR__.'/_keys/ecdsa/public3.key'),
            'private_ec384' => InMemory::file(__DIR__.'/_keys/ecdsa/private_ec384.key'),
            'public_ec384' => InMemory::file(__DIR__.'/_keys/ecdsa/public_ec384.key'),
            'private_ec512' => InMemory::file(__DIR__.'/_keys/ecdsa/private_ec512.key'),
            'public_ec512' => InMemory::file(__DIR__.'/_keys/ecdsa/public_ec512.key'),
            'public2_ec512' => InMemory::file(__DIR__.'/_keys/ecdsa/public2_ec512.key'),
        ];
    }

    #[BeforeClass()]
    public static function createEdDsaKeys(): void
    {
        if (isset(static::$edDsaKeys)) {
            return;
        }

        static::$edDsaKeys = [
            'private' => InMemory::base64Encoded(
                'K3NWT0XqaH+4jgi42gQmHnFE+HTPVhFYi3u4DFJ3OpRHRMt/aGRBoKD/Pt5H/iYgGCla7Q04CdjOUpLSrjZhtg==',
            ),
            'public1' => InMemory::base64Encoded('R0TLf2hkQaCg/z7eR/4mIBgpWu0NOAnYzlKS0q42YbY='),
            'public2' => InMemory::base64Encoded('8uLLzCdMrIWcOrAxS/fteYyJhWIGH+wav2fNz8NZhvI='),
        ];
    }
}
