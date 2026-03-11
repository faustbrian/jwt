<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Validation;

use Cline\JWT\Exceptions\ConstraintViolation;
use Cline\JWT\Exceptions\RequiredConstraintsViolated;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * @author Brian Faust <brian@cline.sh>
 * @internal
 */
#[CoversClass(RequiredConstraintsViolated::class)]
#[UsesClass(ConstraintViolation::class)]
final class RequiredConstraintsViolatedTest extends TestCase
{
    #[Test()]
    public function from_violations_should_configure_message_and_violation_list(): void
    {
        $violation = new ConstraintViolation('testing');
        $exception = RequiredConstraintsViolated::fromViolations($violation);

        $this->assertSame("The token violates some mandatory constraints, details:\n- testing", $exception->getMessage());

        $this->assertSame([$violation], $exception->violations());
    }
}
