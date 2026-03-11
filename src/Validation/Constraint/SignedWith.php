<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Validation\Constraint;

use Cline\JWT\Contracts\Signer\KeyInterface;
use Cline\JWT\Contracts\SignerInterface;
use Cline\JWT\Contracts\TokenInterface;
use Cline\JWT\Contracts\UnencryptedTokenInterface;
use Cline\JWT\Contracts\Validation\SignedWithInterface;
use Cline\JWT\Exceptions\ConstraintViolation;

/**
 * Constraint that verifies both the declared algorithm and the cryptographic signature.
 *
 * Validation happens in two stages: first the token's `alg` header must match the
 * expected signer algorithm, then the signer verifies the payload against the
 * provided key. This guards against accepting a valid signature from an unexpected
 * algorithm implementation.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class SignedWith implements SignedWithInterface
{
    /**
     * @param SignerInterface $signer Signer implementation that defines the accepted algorithm and verification routine
     * @param KeyInterface    $key    Verification key consumed by the signer
     */
    public function __construct(
        private SignerInterface $signer,
        private KeyInterface $key,
    ) {}

    /**
     * Assert that a plain token advertises the expected algorithm and verifies against the configured key.
     *
     * @throws ConstraintViolation
     */
    public function assert(TokenInterface $token): void
    {
        if (!$token instanceof UnencryptedTokenInterface) {
            throw ConstraintViolation::error('You should pass a plain token', $this);
        }

        if ($token->headers()->get('alg') !== $this->signer->algorithmId()) {
            throw ConstraintViolation::error('Token signer mismatch', $this);
        }

        if (!$this->signer->verify($token->signature()->hash(), $token->payload(), $this->key)) {
            throw ConstraintViolation::error('Token signature mismatch', $this);
        }
    }
}
