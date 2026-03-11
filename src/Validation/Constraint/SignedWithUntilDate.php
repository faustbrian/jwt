<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Validation\Constraint;

use Carbon\CarbonInterface;
use Cline\JWT\Contracts\NowProviderInterface;
use Cline\JWT\Contracts\Signer\KeyInterface;
use Cline\JWT\Contracts\SignerInterface;
use Cline\JWT\Contracts\TokenInterface;
use Cline\JWT\Contracts\Validation\SignedWithInterface;
use Cline\JWT\Exceptions\ConstraintViolation;
use Cline\JWT\Support\SystemNowProvider;

/**
 * Signature constraint that expires at a predetermined cutoff time.
 *
 * This wrapper composes {@see SignedWith} and adds an operational deadline for
 * accepting a key. It is useful during key rotation or incident response where a
 * signature should continue to verify only until a known timestamp.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class SignedWithUntilDate implements SignedWithInterface
{
    private SignedWith $verifySignature;

    /**
     * @param CarbonInterface $validUntil Last instant when this signature check may be used
     */
    public function __construct(
        SignerInterface $signer,
        KeyInterface $key,
        private CarbonInterface $validUntil,
        private NowProviderInterface $nowProvider = new SystemNowProvider(),
    ) {
        $this->verifySignature = new SignedWith($signer, $key);
    }

    /**
     * Assert that the constraint itself is still valid, then verify the token signature.
     *
     * Once the cutoff has passed, validation fails before signature verification runs.
     *
     * @throws ConstraintViolation
     */
    public function assert(TokenInterface $token): void
    {
        if ($this->validUntil < $this->nowProvider->now()) {
            throw ConstraintViolation::error(
                'This constraint was only usable until '
                .$this->validUntil->toRfc3339String(),
                $this,
            );
        }

        $this->verifySignature->assert($token);
    }
}
