<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests;

use Carbon\CarbonImmutable;
use Cline\JWT\Configuration;
use Cline\JWT\Contracts\TokenInterface;
use Cline\JWT\Contracts\Validation\ConstraintInterface;
use Cline\JWT\Encoding\ChainedFormatter;
use Cline\JWT\Encoding\JoseEncoder;
use Cline\JWT\Encoding\MicrosecondBasedDateConversion;
use Cline\JWT\Encoding\Support\SodiumBase64Polyfill;
use Cline\JWT\Encoding\UnifyAudience;
use Cline\JWT\Exceptions\ConstraintViolation;
use Cline\JWT\Exceptions\RequiredConstraintsViolated;
use Cline\JWT\Signer\Key\InMemory;
use Cline\JWT\Token\Builder;
use Cline\JWT\Token\Claims;
use Cline\JWT\Token\Headers;
use Cline\JWT\Token\Parser;
use Cline\JWT\Token\Plain;
use Cline\JWT\Token\RegisteredClaims;
use Cline\JWT\Token\Signature;
use Cline\JWT\Validation\Constraint\IdentifiedBy;
use Cline\JWT\Validation\Constraint\IssuedBy;
use Cline\JWT\Validation\Constraint\LooseValidAt;
use Cline\JWT\Validation\Constraint\PermittedFor;
use Cline\JWT\Validation\Validator;
use PHPUnit\Framework\Attributes\After;
use PHPUnit\Framework\Attributes\Before;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

use function throw_if;
use function throw_unless;

/**
 * @author Brian Faust <brian@cline.sh>
 * @internal
 */
#[CoversClass(Configuration::class)]
#[CoversClass(JoseEncoder::class)]
#[CoversClass(ChainedFormatter::class)]
#[CoversClass(MicrosecondBasedDateConversion::class)]
#[CoversClass(UnifyAudience::class)]
#[CoversClass(Builder::class)]
#[CoversClass(Parser::class)]
#[CoversClass(Plain::class)]
#[CoversClass(Claims::class)]
#[CoversClass(Headers::class)]
#[CoversClass(Signature::class)]
#[CoversClass(InMemory::class)]
#[CoversClass(SodiumBase64Polyfill::class)]
#[CoversClass(ConstraintViolation::class)]
#[CoversClass(RequiredConstraintsViolated::class)]
#[CoversClass(Validator::class)]
#[CoversClass(IssuedBy::class)]
#[CoversClass(PermittedFor::class)]
#[CoversClass(IdentifiedBy::class)]
#[CoversClass(LooseValidAt::class)]
final class UnsignedTokenTest extends TestCase
{
    public const int CURRENT_TIME = 100_000;

    private Configuration $config;

    #[Before()]
    public function createConfiguration(): void
    {
        CarbonImmutable::setTestNow(CarbonImmutable::createFromTimestampUTC(self::CURRENT_TIME));

        $this->config = Configuration::forSymmetricSigner(
            new KeyDumpSigner(),
            InMemory::plainText('private'),
        );
    }

    #[After()]
    public function clearTestNow(): void
    {
        CarbonImmutable::setTestNow();
    }

    #[Test()]
    public function builder_can_generate_a_token(): TokenInterface
    {
        $user = ['name' => 'testing', 'email' => 'testing@abc.com'];
        $builder = $this->config->builder();

        $expiration = CarbonImmutable::createFromTimestampUTC(self::CURRENT_TIME + 3_000);

        $token = $builder->identifiedBy('1')
            ->permittedFor('https://client.abc.com')
            ->issuedBy('https://api.abc.com')
            ->expiresAt($expiration)
            ->withClaim('user', $user)
            ->getToken($this->config->signer(), $this->config->signingKey());

        $this->assertEquals(
            new Signature('private', 'cHJpdmF0ZQ'),
            $token->signature(),
        );
        $this->assertEquals(['https://client.abc.com'], $token->claims()->get(RegisteredClaims::AUDIENCE));
        $this->assertSame('https://api.abc.com', $token->claims()->get(RegisteredClaims::ISSUER));
        $this->assertEquals($expiration, $token->claims()->get(RegisteredClaims::EXPIRATION_TIME));
        $this->assertEquals($user, $token->claims()->get('user'));

        return $token;
    }

    #[Test()]
    #[Depends('builder_can_generate_a_token')]
    public function parser_can_read_a_token(TokenInterface $generated): void
    {
        $read = $this->config->parser()->parse($generated->toString());
        $this->assertInstanceOf(Plain::class, $read);

        $this->assertEquals($generated, $read);
        $this->assertSame('testing', $read->claims()->get('user')['name']);
    }

    #[Test()]
    #[Depends('builder_can_generate_a_token')]
    public function token_validation_should_pass_when_everything_is_fine(TokenInterface $generated): void
    {
        $constraints = [
            new IdentifiedBy('1'),
            new PermittedFor('https://client.abc.com'),
            new IssuedBy('https://issuer.abc.com', 'https://api.abc.com'),
            new LooseValidAt(),
        ];

        $this->assertTrue($this->config->validator()->validate($generated, ...$constraints));
    }

    #[Test()]
    #[Depends('builder_can_generate_a_token')]
    public function token_validation_should_allow_custom_constraint(TokenInterface $generated): void
    {
        $this->assertTrue($this->config->validator()->validate($generated, $this->validUserConstraint()));
    }

    #[Test()]
    #[Depends('builder_can_generate_a_token')]
    public function token_assertion_should_raise_exception_when_one_of_the_constraints_fails(TokenInterface $generated): void
    {
        $constraints = [
            new IdentifiedBy('1'),
            new IssuedBy('https://issuer.abc.com'),
        ];

        $this->expectException(RequiredConstraintsViolated::class);
        $this->expectExceptionMessage('The token violates some mandatory constraints');

        $this->config->validator()->assert($generated, ...$constraints);
    }

    private function validUserConstraint(): ConstraintInterface
    {
        return new class() implements ConstraintInterface
        {
            public function assert(TokenInterface $token): void
            {
                throw_unless(
                    $token instanceof Plain,
                    ConstraintViolation::error('Unsigned token constraint requires a plain token.', $this),
                );

                $claims = $token->claims();

                throw_unless(
                    $claims->has('user'),
                    ConstraintViolation::error('Unsigned token constraint requires a user claim.', $this),
                );

                $name = $claims->get('user')['name'] ?? '';
                $email = $claims->get('user')['email'] ?? '';

                throw_if(
                    $name === '' || $email === '',
                    ConstraintViolation::error(
                        'Unsigned token constraint requires non-empty user identity fields.',
                        $this,
                    ),
                );
            }
        };
    }
}
