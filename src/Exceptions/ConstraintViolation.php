<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT\Exceptions;

use Cline\JWT\Contracts\ExceptionInterface;
use Cline\JWT\Contracts\Validation\ConstraintInterface;
use RuntimeException;

/**
 * Represents a single validation rule failure produced by a JWT constraint.
 *
 * Validators use this exception as the atomic failure unit for constraint
 * processing. Each instance carries the human-readable reason plus the concrete
 * constraint class that raised it, which allows higher-level aggregators to
 * build detailed validation reports without losing rule provenance.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class ConstraintViolation extends RuntimeException implements ExceptionInterface
{
    /**
     * Create a violation tied to an optional constraint class name.
     *
     * The constraint identifier is stored separately from the message so callers
     * can inspect or aggregate violations by rule type without parsing strings.
     *
     * @param null|class-string<ConstraintInterface> $constraint
     */
    public function __construct(
        string $message = '',
        public readonly ?string $constraint = null,
    ) {
        parent::__construct($message);
    }

    /**
     * Create a violation from a concrete constraint instance.
     *
     * Constraint implementations call this helper to produce a normalized
     * violation object whose provenance points at the exact rule class that
     * rejected the token.
     *
     * @param non-empty-string $message
     */
    public static function error(string $message, ConstraintInterface $constraint): self
    {
        return new self(message: $message, constraint: $constraint::class);
    }
}
