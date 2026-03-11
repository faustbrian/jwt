<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Signer\Rsa;

use Cline\JWT\Contracts\Signer\KeyInterface;
use Cline\JWT\Signer\Support\OpenSSL;

use const OPENSSL_ALGO_SHA256;

/**
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class KeyValidationSigner extends OpenSSL
{
    public function algorithm(): int
    {
        return OPENSSL_ALGO_SHA256;
    }

    public function algorithmId(): string
    {
        return 'RS256';
    }

    public function sign(string $payload, KeyInterface $key): string
    {
        return $this->createSignature($key, $payload);
    }

    public function verify(string $expected, string $payload, KeyInterface $key): bool
    {
        return $this->verifySignature($expected, $payload, $key);
    }

    // phpcs:ignore SlevomatCodingStandard.Functions.UnusedParameter.UnusedParameter
    protected function guardAgainstIncompatibleKey(int $type, int $lengthInBits): void {}
}
