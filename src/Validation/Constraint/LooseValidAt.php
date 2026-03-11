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
use Cline\JWT\Contracts\Validation\ValidAtInterface;
use Cline\JWT\Exceptions\ConstraintViolation;
use Cline\JWT\Exceptions\LeewayCannotBeNegative;
use Cline\JWT\Support\SystemNowProvider;
use DateInterval;

/**
 * Time-window validator that tolerates missing registered temporal claims.
 *
 * This constraint models the permissive interpretation of JWT validity used when
 * tokens may omit `iat`, `nbf`, or `exp`. Present claims are still enforced, but
 * absent ones are treated as "no restriction" rather than as validation errors.
 * A configurable leeway widens the acceptance window to account for transport
 * delay or clock skew between issuers and consumers.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class LooseValidAt implements ValidAtInterface
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
     * Assert temporal validity using the configured leeway and current time source.
     *
     * Future issue times and not-before values are checked against `now + leeway`,
     * while expiration is checked against `now - leeway` so recently expired tokens
     * can remain acceptable during the skew window.
     *
     * @throws ConstraintViolation
     */
    public function assert(TokenInterface $token): void
    {
        $now = $this->nowProvider->now();

        $this->assertIssueTime($token, $now->add($this->leeway));
        $this->assertMinimumTime($token, $now->add($this->leeway));
        $this->assertExpiration($token, $now->sub($this->leeway));
    }

    /**
     * Normalize leeway configuration and reject negative tolerances.
     *
     * Missing leeway resolves to zero seconds so callers do not need to allocate a
     * `DateInterval` just to express strict clock matching.
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
     * Fail when the token advertises an expiration that falls before the allowed window.
     *
     * @throws ConstraintViolation
     */
    private function assertExpiration(TokenInterface $token, CarbonInterface $now): void
    {
        if ($token->isExpired($now)) {
            throw ConstraintViolation::error('The token is expired', $this);
        }
    }

    /**
     * Fail when the token should not yet be accepted according to its `nbf` claim.
     *
     * @throws ConstraintViolation
     */
    private function assertMinimumTime(TokenInterface $token, CarbonInterface $now): void
    {
        if (!$token->isMinimumTimeBefore($now)) {
            throw ConstraintViolation::error('The token cannot be used yet', $this);
        }
    }

    /**
     * Fail when the token reports an issue time that still lies in the future.
     *
     * @throws ConstraintViolation
     */
    private function assertIssueTime(TokenInterface $token, CarbonInterface $now): void
    {
        if (!$token->hasBeenIssuedBefore($now)) {
            throw ConstraintViolation::error('The token was issued in the future', $this);
        }
    }
}
