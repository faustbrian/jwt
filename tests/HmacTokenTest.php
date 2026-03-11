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
use Cline\JWT\Signer\AbstractHmacSigner;
use Cline\JWT\Signer\Hmac\Sha256;
use Cline\JWT\Signer\Hmac\Sha512;
use Cline\JWT\Signer\Key\InMemory;
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

use function file_put_contents;
use function sys_get_temp_dir;
use function tempnam;

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
#[CoversClass(AbstractHmacSigner::class)]
#[CoversClass(Sha256::class)]
#[CoversClass(Sha512::class)]
#[CoversClass(InvalidKeyProvided::class)]
#[CoversClass(OpenSSL::class)]
#[CoversClass(SodiumBase64Polyfill::class)]
#[CoversClass(Validator::class)]
#[CoversClass(ConstraintViolation::class)]
#[CoversClass(SignedWith::class)]
#[CoversClass(RequiredConstraintsViolated::class)]
final class HmacTokenTest extends TestCase
{
    private Configuration $config;

    #[Before()]
    public function createConfiguration(): void
    {
        $this->config = Configuration::forSymmetricSigner(
            new Sha256(),
            InMemory::base64Encoded('Z0Y6xrhjGQYrEDsP+7aQ3ZAKKERSBeQjP33M0H7Nq6s='),
        );
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
            new SignedWith(
                $this->config->signer(),
                InMemory::base64Encoded('O0MpjL80kE382RyX0rfr9PrNfVclXcdnru2aryanR2o='),
            ),
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
    public function signature_validation_should_succeed_when_key_is_right(TokenInterface $token): void
    {
        $constraint = new SignedWith($this->config->signer(), $this->config->verificationKey());

        $this->assertTrue($this->config->validator()->validate($token, $constraint));
    }

    #[Test()]
    public function everything_should_work_when_using_a_token_generated_by_other_libs(): void
    {
        $config = Configuration::forSymmetricSigner(
            new Sha256(),
            InMemory::base64Encoded('FkL2+V+1k2auI3xxTz/2skChDQVVjT9PW1/grXafg3M='),
        );

        $data = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJoZWxsbyI6IndvcmxkIn0.'
              .'ZQfnc_iFebE--gXmnhJrqMXv3GWdH9uvdkFXTgBcMFw';

        $token = $config->parser()->parse($data);
        $this->assertInstanceOf(Plain::class, $token);
        $constraint = new SignedWith($config->signer(), $config->verificationKey());

        $this->assertTrue($config->validator()->validate($token, $constraint));
        $this->assertSame('world', $token->claims()->get('hello'));
    }

    #[Test()]
    public function signature_validation_with_local_file_key_reference_will_operate_with_key_contents(): void
    {
        $key = tempnam(sys_get_temp_dir(), 'a-very-long-prefix-to-create-a-longer-key');
        $this->assertIsString($key);

        file_put_contents(
            $key,
            SodiumBase64Polyfill::base642bin(
                'FkL2+V+1k2auI3xxTz/2skChDQVVjT9PW1/grXafg3M=',
                SodiumBase64Polyfill::SODIUM_BASE64_VARIANT_ORIGINAL,
            ),
        );

        $validKey = InMemory::file($key);
        $invalidKey = InMemory::plainText('file://'.$key);
        $signer = new Sha256();
        $configuration = Configuration::forSymmetricSigner($signer, $validKey);
        $validator = $configuration->validator();

        $token = $configuration->builder()
            ->withClaim('foo', 'bar')
            ->getToken($configuration->signer(), $configuration->signingKey());

        $this->assertFalse($validator->validate(
            $token,
            new SignedWith($signer, $invalidKey),
        ), 'TokenInterface cannot be validated against the **path** of the key');

        $this->assertTrue($validator->validate(
            $token,
            new SignedWith($signer, $validKey),
        ), 'TokenInterface can be validated against the **contents** of the key');
    }
}
