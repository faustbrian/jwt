<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Validation;

use Cline\JWT\Contracts\TokenInterface;
use Cline\JWT\Contracts\Validation\ConstraintInterface;
use Cline\JWT\Exceptions\ConstraintViolation;
use Cline\JWT\Exceptions\NoConstraintsGiven;
use Cline\JWT\Exceptions\RequiredConstraintsViolated;
use Cline\JWT\Validation\Validator;
use PHPUnit\Framework\Attributes\Before;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;

/**
 * @author Brian Faust <brian@cline.sh>
 * @internal
 */
#[CoversClass(Validator::class)]
#[UsesClass(ConstraintViolation::class)]
#[UsesClass(RequiredConstraintsViolated::class)]
final class ValidatorTest extends TestCase
{
    private TokenInterface&Stub $token;

    #[Before()]
    public function createDependencies(): void
    {
        $this->token = $this->createStub(TokenInterface::class);
    }

    #[Test()]
    public function assert_should_raise_exception_when_no_constraint_is_given(): void
    {
        $validator = new Validator();

        $this->expectException(NoConstraintsGiven::class);

        $validator->assert($this->token, ...[]);
    }

    #[Test()]
    public function assert_should_raise_exception_when_at_least_one_constraint_fails(): void
    {
        $failedConstraint = $this->createMock(ConstraintInterface::class);
        $successfulConstraint = $this->createMock(ConstraintInterface::class);

        $failedConstraint->expects($this->once())
            ->method('assert')
            ->willThrowException(
                new ConstraintViolation(),
            );

        $successfulConstraint->expects($this->once())
            ->method('assert');

        $validator = new Validator();

        $this->expectException(RequiredConstraintsViolated::class);
        $this->expectExceptionMessage('The token violates some mandatory constraints');

        $validator->assert(
            $this->token,
            $failedConstraint,
            $successfulConstraint,
        );
    }

    #[Test()]
    public function assert_should_not_raise_exception_when_no_constraint_fails(): void
    {
        $constraint = $this->createMock(ConstraintInterface::class);
        $constraint->expects($this->once())->method('assert');

        $validator = new Validator();

        $validator->assert($this->token, $constraint);
        $this->addToAssertionCount(1);
    }

    #[Test()]
    public function validate_should_raise_exception_when_no_constraint_is_given(): void
    {
        $validator = new Validator();

        $this->expectException(NoConstraintsGiven::class);

        $validator->validate($this->token);
    }

    #[Test()]
    public function validate_should_return_false_when_at_least_one_constraint_fails(): void
    {
        $failedConstraint = $this->createMock(ConstraintInterface::class);
        $successfulConstraint = $this->createMock(ConstraintInterface::class);

        $failedConstraint->expects($this->once())
            ->method('assert')
            ->willThrowException(
                new ConstraintViolation(),
            );

        $successfulConstraint->expects($this->never())
            ->method('assert');

        $validator = new Validator();

        $this->assertFalse($validator->validate(
            $this->token,
            $failedConstraint,
            $successfulConstraint,
        ));
    }

    #[Test()]
    public function validate_should_return_true_when_no_constraint_fails(): void
    {
        $constraint = $this->createMock(ConstraintInterface::class);
        $constraint->expects($this->once())->method('assert');

        $validator = new Validator();
        $this->assertTrue($validator->validate($this->token, $constraint));
    }
}
