<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests;

use Cline\JWT\Configuration;
use Cline\JWT\Contracts\TokenInterface;
use Cline\JWT\Encoding\ChainedFormatter;
use Cline\JWT\Encoding\JoseEncoder;
use Cline\JWT\Encoding\MicrosecondBasedDateConversion;
use Cline\JWT\Encoding\Support\SodiumBase64Polyfill;
use Cline\JWT\Encoding\UnifyAudience;
use Cline\JWT\Exceptions\ConstraintViolation;
use Cline\JWT\Exceptions\InvalidKeyProvided;
use Cline\JWT\Exceptions\RequiredConstraintsViolated;
use Cline\JWT\Signer\AbstractRsaSigner;
use Cline\JWT\Signer\Key\InMemory;
use Cline\JWT\Signer\Rsa\Sha256;
use Cline\JWT\Signer\Rsa\Sha512;
use Cline\JWT\Signer\Support\OpenSSL;
use Cline\JWT\Token\Builder;
use Cline\JWT\Token\Claims;
use Cline\JWT\Token\Headers;
use Cline\JWT\Token\Parser;
use Cline\JWT\Token\Plain;
use Cline\JWT\Token\RegisteredClaims;
use Cline\JWT\Token\Signature;
use Cline\JWT\Validation\Constraint\SignedWith;
use Cline\JWT\Validation\Validator;
use PHPUnit\Framework\Attributes\Before;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Tests\Keys;

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
#[CoversClass(InvalidKeyProvided::class)]
#[CoversClass(OpenSSL::class)]
#[CoversClass(AbstractRsaSigner::class)]
#[CoversClass(Sha256::class)]
#[CoversClass(Sha512::class)]
#[CoversClass(InMemory::class)]
#[CoversClass(SodiumBase64Polyfill::class)]
#[CoversClass(ConstraintViolation::class)]
#[CoversClass(RequiredConstraintsViolated::class)]
#[CoversClass(Validator::class)]
#[CoversClass(SignedWith::class)]
final class RsaTokenTest extends TestCase
{
    use Keys;

    private Configuration $config;

    #[Before()]
    public function createConfiguration(): void
    {
        $this->config = Configuration::forAsymmetricSigner(
            new Sha256(),
            self::$rsaKeys['private'],
            self::$rsaKeys['public'],
        );
    }

    #[Test()]
    public function builder_should_raise_exception_when_key_is_invalid(): void
    {
        $builder = $this->config->builder()
            ->identifiedBy('1')
            ->permittedFor('https://client.abc.com')
            ->issuedBy('https://api.abc.com')
            ->withClaim('user', ['name' => 'testing', 'email' => 'testing@abc.com']);

        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage('It was not possible to parse your key');

        $builder->getToken($this->config->signer(), InMemory::plainText('testing'));
    }

    #[Test()]
    public function builder_should_raise_exception_when_key_is_not_rsa_compatible(): void
    {
        $builder = $this->config->builder()
            ->identifiedBy('1')
            ->permittedFor('https://client.abc.com')
            ->issuedBy('https://api.abc.com')
            ->withClaim('user', ['name' => 'testing', 'email' => 'testing@abc.com']);

        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage('The type of the provided key is not "RSA", "EC" provided');

        $builder->getToken($this->config->signer(), self::$ecdsaKeys['private']);
    }

    #[Test()]
    public function builder_can_generate_a_token(): TokenInterface
    {
        $user = ['name' => 'testing', 'email' => 'testing@abc.com'];
        $builder = $this->config->builder();

        $token = $builder->identifiedBy('1')
            ->permittedFor('https://client.abc.com')
            ->issuedBy('https://api.abc.com')
            ->withClaim('user', $user)
            ->withHeader('jki', '1234')
            ->getToken($this->config->signer(), $this->config->signingKey());

        $this->assertSame('1234', $token->headers()->get('jki'));
        $this->assertSame(['https://client.abc.com'], $token->claims()->get(RegisteredClaims::AUDIENCE));
        $this->assertSame('https://api.abc.com', $token->claims()->get(RegisteredClaims::ISSUER));
        $this->assertSame($user, $token->claims()->get('user'));

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
    public function signature_assertion_should_raise_exception_when_key_is_not_right(TokenInterface $token): void
    {
        $this->expectException(RequiredConstraintsViolated::class);
        $this->expectExceptionMessage('The token violates some mandatory constraints');

        $this->config->validator()->assert(
            $token,
            new SignedWith($this->config->signer(), self::$rsaKeys['encrypted-public']),
        );
    }

    #[Test()]
    #[Depends('builder_can_generate_a_token')]
    public function signature_assertion_should_raise_exception_when_algorithm_is_different(TokenInterface $token): void
    {
        $this->expectException(RequiredConstraintsViolated::class);
        $this->expectExceptionMessage('The token violates some mandatory constraints');

        $this->config->validator()->assert(
            $token,
            new SignedWith(
                new Sha512(),
                $this->config->verificationKey(),
            ),
        );
    }

    #[Test()]
    #[Depends('builder_can_generate_a_token')]
    public function signature_assertion_should_raise_exception_when_key_is_not_rsa_compatible(TokenInterface $token): void
    {
        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage('The type of the provided key is not "RSA", "EC" provided');

        $this->config->validator()->assert(
            $token,
            new SignedWith(
                $this->config->signer(),
                self::$ecdsaKeys['public1'],
            ),
        );
    }

    #[Test()]
    #[Depends('builder_can_generate_a_token')]
    public function signature_validation_should_succeed_when_key_is_right(TokenInterface $token): void
    {
        $constraint = new SignedWith($this->config->signer(), $this->config->verificationKey());

        $this->assertTrue($this->config->validator()->validate($token, $constraint));
    }

    #[Test()]
    public function everything_should_work_when_using_a_token_generated_by_other_libs(): void
    {
        $data = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXUyJ9.eyJoZWxsbyI6IndvcmxkIn0.s'
                .'GYbB1KrmnESNfJ4D9hOe1Zad_BMyxdb8G4p4LNP7StYlOyBWck6q7XPpPj_6gB'
                .'Bo1ohD3MA2o0HY42lNIrAStaVhfsFKGdIou8TarwMGZBPcif_3ThUV1pGS3fZc'
                .'lFwF2SP7rqCngQis_xcUVCyqa8E1Wa_v28grnl1QZrnmQFO8B5JGGLqcrfUHJO'
                .'nJCupP-Lqh4TmIhftIimSCgLNmJg80wyrpUEfZYReE7hPuEmY0ClTqAGIMQoNS'
                .'98ljwDxwhfbSuL2tAdbV4DekbTpWzspe3dOJ7RSzmPKVZ6NoezaIazKqyqkmHZfcMaHI1lQeGia6LTbHU1bp0gINi74Vw';

        $token = $this->config->parser()->parse($data);
        $this->assertInstanceOf(Plain::class, $token);
        $constraint = new SignedWith($this->config->signer(), $this->config->verificationKey());

        $this->assertTrue($this->config->validator()->validate($token, $constraint));
        $this->assertSame('world', $token->claims()->get('hello'));
    }
}
