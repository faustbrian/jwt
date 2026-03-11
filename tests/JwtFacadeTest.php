<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests;

use AssertionError;
use Carbon\CarbonImmutable;
use Cline\JWT\Encoding\ChainedFormatter;
use Cline\JWT\Encoding\JoseEncoder;
use Cline\JWT\Encoding\Support\SodiumBase64Polyfill;
use Cline\JWT\Encoding\UnifyAudience;
use Cline\JWT\Encoding\UnixTimestampDates;
use Cline\JWT\Exceptions\ConstraintViolation;
use Cline\JWT\Exceptions\RequiredConstraintsViolated;
use Cline\JWT\IssueTokenRequest;
use Cline\JWT\JwtFacade;
use Cline\JWT\Signer\AbstractHmacSigner;
use Cline\JWT\Signer\Hmac\Sha256;
use Cline\JWT\Signer\Hmac\Sha384;
use Cline\JWT\Signer\Key\InMemory;
use Cline\JWT\Token\Builder;
use Cline\JWT\Token\Claims;
use Cline\JWT\Token\Headers;
use Cline\JWT\Token\Parser;
use Cline\JWT\Token\Plain;
use Cline\JWT\Token\Signature;
use Cline\JWT\Validation\Constraint\IssuedBy;
use Cline\JWT\Validation\Constraint\SignedWith;
use Cline\JWT\Validation\Constraint\SignedWithOneInSet;
use Cline\JWT\Validation\Constraint\SignedWithUntilDate;
use Cline\JWT\Validation\Constraint\StrictValidAt;
use Cline\JWT\Validation\Validator;
use DateInterval;
use PHPUnit\Framework\Attributes\After;
use PHPUnit\Framework\Attributes\Before;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * @author Brian Faust <brian@cline.sh>
 * @internal
 */
#[CoversClass(JwtFacade::class)]
#[UsesClass(Builder::class)]
#[UsesClass(Parser::class)]
#[UsesClass(Plain::class)]
#[UsesClass(Claims::class)]
#[UsesClass(Headers::class)]
#[UsesClass(Signature::class)]
#[UsesClass(JoseEncoder::class)]
#[UsesClass(ChainedFormatter::class)]
#[UsesClass(UnixTimestampDates::class)]
#[UsesClass(UnifyAudience::class)]
#[UsesClass(AbstractHmacSigner::class)]
#[UsesClass(Sha256::class)]
#[UsesClass(Sha384::class)]
#[UsesClass(SodiumBase64Polyfill::class)]
#[UsesClass(InMemory::class)]
#[UsesClass(Validator::class)]
#[UsesClass(IssuedBy::class)]
#[UsesClass(SignedWith::class)]
#[UsesClass(SignedWithOneInSet::class)]
#[UsesClass(SignedWithUntilDate::class)]
#[UsesClass(StrictValidAt::class)]
#[UsesClass(ConstraintViolation::class)]
#[UsesClass(RequiredConstraintsViolated::class)]
final class JwtFacadeTest extends TestCase
{
    private CarbonImmutable $now;

    private Sha256 $signer;

    private InMemory $key;

    /** @var non-empty-string */
    private string $issuer;

    #[Before()]
    public function configureDependencies(): void
    {
        $this->now = CarbonImmutable::parse('2021-07-10');
        CarbonImmutable::setTestNow($this->now);
        $this->signer = new Sha256();
        $this->key = InMemory::base64Encoded('qOIXmZRqZKY80qg0BjtCrskM6OK7gPOea8mz1H7h/dE=');
        $this->issuer = 'bar';
    }

    #[After()]
    public function clearTestNow(): void
    {
        CarbonImmutable::setTestNow();
    }

    #[Test()]
    public function issue_set_time_validity(): void
    {
        $token = new JwtFacade()->issue(
            $this->signer,
            $this->key,
            new IssueTokenRequest(),
        );

        $now = $this->now;

        $this->assertTrue($token->hasBeenIssuedBefore($now));
        $this->assertTrue($token->isMinimumTimeBefore($now));
        $this->assertFalse($token->isExpired($now));

        $aYearAgo = $now->modify('-1 year');

        $this->assertFalse($token->hasBeenIssuedBefore($aYearAgo));
        $this->assertFalse($token->isMinimumTimeBefore($aYearAgo));
        $this->assertFalse($token->isExpired($aYearAgo));

        $inOneYear = $now->modify('+1 year');

        $this->assertTrue($token->hasBeenIssuedBefore($inOneYear));
        $this->assertTrue($token->isMinimumTimeBefore($inOneYear));
        $this->assertTrue($token->isExpired($inOneYear));
    }

    #[Test()]
    public function issue_allows_time_validity_overwrite(): void
    {
        $then = CarbonImmutable::parse('2001-02-03 04:05:06');
        $token = new JwtFacade()->issue(
            $this->signer,
            $this->key,
            new IssueTokenRequest()
                ->issuedAt($then)
                ->canOnlyBeUsedAfter($then)
                ->expiresAt($then->modify('+1 minute')),
        );

        $now = $then->modify('+30 seconds');

        $this->assertTrue($token->hasBeenIssuedBefore($now));
        $this->assertTrue($token->isMinimumTimeBefore($now));
        $this->assertFalse($token->isExpired($now));

        $aYearAgo = $then->modify('-1 year');

        $this->assertFalse($token->hasBeenIssuedBefore($aYearAgo));
        $this->assertFalse($token->isMinimumTimeBefore($aYearAgo));
        $this->assertFalse($token->isExpired($aYearAgo));

        $inOneYear = $then->modify('+1 year');

        $this->assertTrue($token->hasBeenIssuedBefore($inOneYear));
        $this->assertTrue($token->isMinimumTimeBefore($inOneYear));
        $this->assertTrue($token->isExpired($inOneYear));
    }

    #[Test()]
    public function good_jwt(): void
    {
        $token = new JwtFacade()->parse(
            $this->createToken(),
            new SignedWith($this->signer, $this->key),
            new StrictValidAt(),
            new IssuedBy($this->issuer),
        );

        $this->assertInstanceOf(Plain::class, $token);
    }

    #[Test()]
    public function bad_signer(): void
    {
        $this->expectException(RequiredConstraintsViolated::class);
        $this->expectExceptionMessage('Token signer mismatch');

        (void) new JwtFacade()->parse(
            $this->createToken(),
            new SignedWith(
                new Sha384(),
                $this->key,
            ),
            new StrictValidAt(),
            new IssuedBy($this->issuer),
        );
    }

    #[Test()]
    public function bad_key(): void
    {
        $this->expectException(RequiredConstraintsViolated::class);
        $this->expectExceptionMessage('Token signature mismatch');

        (void) new JwtFacade()->parse(
            $this->createToken(),
            new SignedWith(
                $this->signer,
                InMemory::base64Encoded('czyPTpN595zVNSuvoNNlXCRFgXS2fHscMR36dGojaUE='),
            ),
            new StrictValidAt(),
            new IssuedBy($this->issuer),
        );
    }

    #[Test()]
    public function bad_time(): void
    {
        $token = $this->createToken();
        $this->now = $this->now->modify('+30 days');
        CarbonImmutable::setTestNow($this->now);

        $this->expectException(RequiredConstraintsViolated::class);
        $this->expectExceptionMessage('The token is expired');

        (void) new JwtFacade()->parse(
            $token,
            new SignedWith($this->signer, $this->key),
            new StrictValidAt(),
            new IssuedBy($this->issuer),
        );
    }

    #[Test()]
    public function bad_issuer(): void
    {
        $this->expectException(RequiredConstraintsViolated::class);
        $this->expectExceptionMessage('The token was not issued by the given issuers');

        (void) new JwtFacade()->parse(
            $this->createToken(),
            new SignedWith($this->signer, $this->key),
            new StrictValidAt(),
            new IssuedBy('xyz'),
        );
    }

    #[Test()]
    public function parser_for_non_unencrypted_tokens(): void
    {
        $this->expectException(AssertionError::class);

        (void) new JwtFacade(
            new UnsupportedParser(),
        )->parse(
            'a.very-broken.token',
            new SignedWith($this->signer, $this->key),
            new StrictValidAt(),
            new IssuedBy($this->issuer),
        );
    }

    #[Test()]
    public function custom_carbon_now(): void
    {
        $now = CarbonImmutable::parse('2021-07-10');
        CarbonImmutable::setTestNow($now);

        $facade = new JwtFacade();

        $token = $facade->issue(
            $this->signer,
            $this->key,
            new IssueTokenRequest(),
        );

        $this->assertEquals($token, $facade->parse(
            $token->toString(),
            new SignedWith($this->signer, $this->key),
            new StrictValidAt(),
        ));
    }

    #[Test()]
    public function multiple_keys(): void
    {
        $now = CarbonImmutable::parse('2023-11-19 22:10:00');
        CarbonImmutable::setTestNow($now);

        $token = new JwtFacade()->parse(
            $this->createToken(),
            new SignedWithOneInSet(
                new SignedWithUntilDate(
                    $this->signer,
                    InMemory::base64Encoded('czyPTpN595zVNSuvoNNlXCRFgXS2fHscMR36dGojaUE='),
                    CarbonImmutable::parse('2024-11-19 22:10:00'),
                ),
                new SignedWithUntilDate(
                    $this->signer,
                    $this->key,
                    CarbonImmutable::parse('2025-11-19 22:10:00'),
                ),
            ),
            new StrictValidAt(),
            new IssuedBy($this->issuer),
        );

        $this->assertInstanceOf(Plain::class, $token);
    }

    /**
     * @return non-empty-string
     */
    private function createToken(): string
    {
        return new JwtFacade()->issue(
            $this->signer,
            $this->key,
            new IssueTokenRequest()
                ->issuedBy($this->issuer)
                ->expiresAfter(
                    new DateInterval('PT5M'),
                ),
        )->toString();
    }
}
