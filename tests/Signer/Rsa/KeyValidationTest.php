<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Signer\Rsa;

use Cline\JWT\Exceptions\CannotSignPayload;
use Cline\JWT\Signer\Key\InMemory;
use Cline\JWT\Signer\Support\OpenSSL;
use PHPUnit\Framework\Attributes\After;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

use const PHP_EOL;

use function openssl_error_string;

/**
 * @author Brian Faust <brian@cline.sh>
 * @internal
 */
#[CoversClass(OpenSSL::class)]
#[CoversClass(CannotSignPayload::class)]
#[UsesClass(InMemory::class)]
final class KeyValidationTest extends TestCase
{
    #[After()]
    public function clearOpenSSLErrors(): void
    {
        // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedWhile
        while (openssl_error_string()) {
        }
    }

    #[Test()]
    public function sign_should_raise_an_exception_when_key_is_invalid(): void
    {
        $key = <<<'KEY_WRAP'
        -----BEGIN RSA PRIVATE KEY-----
        MGECAQACEQC4MRKSVsq5XnRBrJoX6+rnAgMBAAECECO8SZkgw6Yg66A6SUly/3kC
        CQDtPXZtCQWJuwIJAMbBu17GDOrFAggopfhNlFcjkwIIVjb7G+U0/TECCEERyvxP
        TWdN
        -----END RSA PRIVATE KEY-----
        KEY_WRAP;

        $this->expectException(CannotSignPayload::class);
        $this->expectExceptionMessage('There was an error while creating the signature:'.PHP_EOL.'* error:');

        $this->algorithm()->sign('testing', InMemory::plainText($key));
    }

    private function algorithm(): KeyValidationSigner
    {
        return new KeyValidationSigner();
    }
}
