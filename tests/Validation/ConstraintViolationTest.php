<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Validation;

use Cline\JWT\Exceptions\ConstraintViolation;
use Cline\JWT\Validation\Constraint\IdentifiedBy;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * @author Brian Faust <brian@cline.sh>
 * @internal
 */
#[CoversClass(ConstraintViolation::class)]
#[UsesClass(IdentifiedBy::class)]
final class ConstraintViolationTest extends TestCase
{
    #[Test()]
    public function error_should_configure_message_and_constraint(): void
    {
        $violation = ConstraintViolation::error('testing', new IdentifiedBy('token id'));

        $this->assertSame('testing', $violation->getMessage());
        $this->assertSame(IdentifiedBy::class, $violation->constraint);
    }
}
