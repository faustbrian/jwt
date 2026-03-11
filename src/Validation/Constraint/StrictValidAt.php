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
use Cline\JWT\Contracts\TokenInterface;
use Cline\JWT\Contracts\UnencryptedTokenInterface;
use Cline\JWT\Contracts\Validation\ValidAtInterface;
use Cline\JWT\Exceptions\ConstraintViolation;
use Cline\JWT\Exceptions\LeewayCannotBeNegative;
use Cline\JWT\Support\SystemNowProvider;
use Cline\JWT\Token\RegisteredClaims;
use DateInterval;

/**
 * Time-window validator that requires the full set of registered temporal claims.
 *
 * Unlike {@see LooseValidAt}, this constraint enforces both the presence and the
 * semantics of `iat`, `nbf`, and `exp`. It is intended for consumers that treat
 * missing temporal claims as malformed tokens rather than as omitted safeguards.
 * A positive leeway still softens comparisons to absorb distributed clock skew.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class StrictValidAt implements ValidAtInterface
{
    private DateInterval $leeway;

    /**
     * @param null|DateInterval $leeway Positive clock-skew tolerance applied symmetrically around "now"
     */
    public function __construct(
        ?DateInterval $leeway = null,
        private NowProviderInterface $nowProvider = new SystemNowProvider(),
    ) {
        $this->leeway = $this->guardLeeway($leeway);
    }

    /**
     * Assert that a plain token includes and satisfies all temporal registered claims.
     *
     * This constraint rejects non-plain tokens up front because encrypted or opaque
     * tokens cannot expose the required registered claims for inspection.
     *
     * @throws ConstraintViolation
     */
    public function assert(TokenInterface $token): void
    {
        if (!$token instanceof UnencryptedTokenInterface) {
            throw ConstraintViolation::error('You should pass a plain token', $this);
        }

        $now = $this->nowProvider->now();

        $this->assertIssueTime($token, $now->add($this->leeway));
        $this->assertMinimumTime($token, $now->add($this->leeway));
        $this->assertExpiration($token, $now->sub($this->leeway));
    }

    /**
     * Normalize leeway configuration and reject negative tolerances.
     */
    private function guardLeeway(?DateInterval $leeway): DateInterval
    {
        if (!$leeway instanceof DateInterval) {
            return new DateInterval('PT0S');
        }

        if ($leeway->invert === 1) {
            throw LeewayCannotBeNegative::create();
        }

        return $leeway;
    }

    /**
     * Require the `exp` claim and ensure the token has not expired.
     *
     * @throws ConstraintViolation
     */
    private function assertExpiration(UnencryptedTokenInterface $token, CarbonInterface $now): void
    {
        if (!$token->claims()->has(RegisteredClaims::EXPIRATION_TIME)) {
            throw ConstraintViolation::error('"Expiration Time" claim missing', $this);
        }

        if ($token->isExpired($now)) {
            throw ConstraintViolation::error('The token is expired', $this);
        }
    }

    /**
     * Require the `nbf` claim and ensure the token is already usable.
     *
     * @throws ConstraintViolation
     */
    private function assertMinimumTime(UnencryptedTokenInterface $token, CarbonInterface $now): void
    {
        if (!$token->claims()->has(RegisteredClaims::NOT_BEFORE)) {
            throw ConstraintViolation::error('"Not Before" claim missing', $this);
        }

        if (!$token->isMinimumTimeBefore($now)) {
            throw ConstraintViolation::error('The token cannot be used yet', $this);
        }
    }

    /**
     * Require the `iat` claim and ensure it does not lie in the future.
     *
     * @throws ConstraintViolation
     */
    private function assertIssueTime(UnencryptedTokenInterface $token, CarbonInterface $now): void
    {
        if (!$token->claims()->has(RegisteredClaims::ISSUED_AT)) {
            throw ConstraintViolation::error('"Issued At" claim missing', $this);
        }

        if (!$token->hasBeenIssuedBefore($now)) {
            throw ConstraintViolation::error('The token was issued in the future', $this);
        }
    }
}
