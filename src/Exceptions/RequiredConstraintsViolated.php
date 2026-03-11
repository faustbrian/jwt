<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Exceptions;

use Cline\JWT\Contracts\ExceptionInterface;
use RuntimeException;

use function array_map;
use function implode;

/**
 * Aggregates one or more mandatory JWT validation failures.
 *
 * `Validator::assert()` collects every failing constraint instead of stopping at
 * the first error so callers can see the full set of reasons a token was rejected.
 * This exception is the package-level wrapper for that aggregate result and keeps
 * the underlying `ConstraintViolation` objects available for programmatic handling.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class RequiredConstraintsViolated extends RuntimeException implements ExceptionInterface
{
    /**
     * Create an aggregate exception from a precomputed message and violation list.
     *
     * @param array<ConstraintViolation> $violations Constraint failures collected during validation
     */
    public function __construct(
        string $message = '',
        public readonly array $violations = [],
    ) {
        parent::__construct($message);
    }

    /**
     * Create an aggregate exception from individual violations.
     *
     * This factory preserves each concrete violation while also generating the
     * multi-line summary message exposed by the exception itself.
     */
    public static function fromViolations(ConstraintViolation ...$violations): self
    {
        return new self(message: self::buildMessage($violations), violations: $violations);
    }

    /**
     * Return the collected violations in the order they were produced.
     *
     * Callers can use this to inspect individual failure reasons after catching
     * the aggregate exception.
     *
     * @return array<ConstraintViolation>
     */
    public function violations(): array
    {
        return $this->violations;
    }

    /**
     * Build the human-readable summary used by the aggregate exception.
     *
     * Each violation is rendered as a bullet line so log output and exception
     * messages preserve the complete validation failure set.
     *
     * @param array<ConstraintViolation> $violations
     */
    private static function buildMessage(array $violations): string
    {
        $violations = array_map(
            static fn (ConstraintViolation $violation): string => '- '.$violation->getMessage(),
            $violations,
        );

        $message = "The token violates some mandatory constraints, details:\n";

        return $message.implode("\n", $violations);
    }
}
