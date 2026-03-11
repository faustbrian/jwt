<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Token;

use Carbon\CarbonImmutable;
use Cline\JWT\Contracts\EncoderInterface;
use Cline\JWT\Contracts\SignerInterface;
use Cline\JWT\Encoding\MicrosecondBasedDateConversion;
use Cline\JWT\Exceptions\RegisteredClaimGiven;
use Cline\JWT\Signer\Key\InMemory;
use Cline\JWT\Token\Builder;
use Cline\JWT\Token\Claims;
use Cline\JWT\Token\Headers;
use Cline\JWT\Token\Plain;
use Cline\JWT\Token\RegisteredClaims;
use Cline\JWT\Token\Signature;
use PHPUnit\Framework\Attributes\Before;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SplObjectStorage;

/**
 * @author Brian Faust <brian@cline.sh>
 * @internal
 */
#[CoversClass(Builder::class)]
#[CoversClass(RegisteredClaimGiven::class)]
#[UsesClass(MicrosecondBasedDateConversion::class)]
#[UsesClass(InMemory::class)]
#[UsesClass(Plain::class)]
#[UsesClass(Signature::class)]
#[UsesClass(Claims::class)]
#[UsesClass(Headers::class)]
final class BuilderTest extends TestCase
{
    private EncoderInterface&MockObject $encoder;

    private SignerInterface&MockObject $signer;

    #[Before()]
    public function initializeDependencies(): void
    {
        $this->encoder = $this->createMock(EncoderInterface::class);
        $this->signer = $this->createMock(SignerInterface::class);
        $this->signer->method('algorithmId')->willReturn('RS256');
    }

    #[Test()]
    public function with_claim_should_raise_exception_when_trying_to_configure_a_registered_claim(): void
    {
        $this->encoder->expects($this->never())->method($this->anything());
        $this->signer->expects($this->never())->method($this->anything());

        $builder = Builder::new($this->encoder, new MicrosecondBasedDateConversion());

        $this->expectException(RegisteredClaimGiven::class);
        $this->expectExceptionMessage(
            'Builder#withClaim() is meant to be used for non-registered claims, '
            .'check the documentation on how to set claim "iss"',
        );

        $builder->withClaim(RegisteredClaims::ISSUER, 'me');
    }

    #[Test()]
    public function get_token_should_return_a_completely_configure_token(): void
    {
        $issuedAt = CarbonImmutable::parse('@1487285080');
        $notBefore = CarbonImmutable::createFromFormat('U.u', '1487285080.000123');
        $expiration = CarbonImmutable::createFromFormat('U.u', '1487285080.123456');

        $this->assertInstanceOf(CarbonImmutable::class, $notBefore);
        $this->assertInstanceOf(CarbonImmutable::class, $expiration);

        $this->encoder->expects($this->exactly(2))
            ->method('jsonEncode')
            ->willReturnOnConsecutiveCalls('1', '2');

        $this->encoder->expects($this->exactly(3))
            ->method('base64UrlEncode')
            ->willReturnArgument(0);

        $this->signer->expects($this->once())
            ->method('sign')
            ->with('1.2')
            ->willReturn('3');

        $builder = Builder::new($this->encoder, new MicrosecondBasedDateConversion());
        $token = $builder->identifiedBy('123456')
            ->issuedBy('https://issuer.com')
            ->issuedAt($issuedAt)
            ->canOnlyBeUsedAfter($notBefore)
            ->expiresAt($expiration)
            ->relatedTo('subject')
            ->permittedFor('test1')
            ->permittedFor('test2')
            ->permittedFor('test2') // should not be added since it's duplicated
            ->withClaim('test', 123)
            ->withHeader('userId', 2)
            ->getToken($this->signer, InMemory::plainText('123'));

        $this->assertSame('JWT', $token->headers()->get('typ'));
        $this->assertSame('RS256', $token->headers()->get('alg'));
        $this->assertSame(2, $token->headers()->get('userId'));
        $this->assertSame(123, $token->claims()->get('test'));
        $this->assertSame($issuedAt, $token->claims()->get(RegisteredClaims::ISSUED_AT));
        $this->assertSame($notBefore, $token->claims()->get(RegisteredClaims::NOT_BEFORE));
        $this->assertSame($expiration, $token->claims()->get(RegisteredClaims::EXPIRATION_TIME));
        $this->assertSame('123456', $token->claims()->get(RegisteredClaims::ID));
        $this->assertSame('https://issuer.com', $token->claims()->get(RegisteredClaims::ISSUER));
        $this->assertSame('subject', $token->claims()->get(RegisteredClaims::SUBJECT));
        $this->assertSame(['test1', 'test2'], $token->claims()->get(RegisteredClaims::AUDIENCE));
        $this->assertSame('3', $token->signature()->toString());
    }

    #[Test()]
    public function immutability(): void
    {
        $this->encoder->expects($this->never())->method($this->anything());
        $this->signer->expects($this->never())->method($this->anything());

        $map = new SplObjectStorage();
        $builder = Builder::new($this->encoder, new MicrosecondBasedDateConversion());
        $map[$builder] = true;
        $builder = $builder->identifiedBy('123456');
        $map[$builder] = true;
        $builder = $builder->issuedBy('https://issuer.com');
        $map[$builder] = true;
        $builder = $builder->issuedAt(CarbonImmutable::now());
        $map[$builder] = true;
        $builder = $builder->canOnlyBeUsedAfter(CarbonImmutable::now());
        $map[$builder] = true;
        $builder = $builder->expiresAt(CarbonImmutable::now());
        $map[$builder] = true;
        $builder = $builder->relatedTo('subject');
        $map[$builder] = true;
        $builder = $builder->permittedFor('test1');
        $map[$builder] = true;
        $builder = $builder->withClaim('test', 123);
        $map[$builder] = true;
        $builder = $builder->withHeader('userId', 2);
        $map[$builder] = true;

        $this->assertCount(10, $map);
    }
}
