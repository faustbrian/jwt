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
use Cline\JWT\Encoding\ChainedFormatter;
use Cline\JWT\Encoding\JoseEncoder;
use Cline\JWT\Encoding\MicrosecondBasedDateConversion;
use Cline\JWT\Encoding\Support\SodiumBase64Polyfill;
use Cline\JWT\Encoding\UnifyAudience;
use Cline\JWT\Signer\Key\InMemory;
use Cline\JWT\Token\Builder;
use Cline\JWT\Token\Claims;
use Cline\JWT\Token\Headers;
use Cline\JWT\Token\Parser;
use Cline\JWT\Token\Plain;
use Cline\JWT\Token\Signature;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

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
final class TimeFractionPrecisionTest extends TestCase
{
    #[Test()]
    #[DataProvider('provideTime_fractions_precisions_are_respectedCases')]
    public function time_fractions_precisions_are_respected(string $timeFraction): void
    {
        $config = Configuration::forSymmetricSigner(
            new KeyDumpSigner(),
            InMemory::plainText('private'),
        );

        $issuedAt = CarbonImmutable::createFromFormat('U.u', $timeFraction);

        $this->assertInstanceOf(CarbonImmutable::class, $issuedAt);
        $this->assertSame($timeFraction, $issuedAt->format('U.u'));

        $token = $config->builder()
            ->issuedAt($issuedAt)
            ->getToken($config->signer(), $config->signingKey());

        $parsedToken = $config->parser()->parse($token->toString());

        $this->assertInstanceOf(Plain::class, $parsedToken);
        $this->assertSame($timeFraction, $parsedToken->claims()->get('iat')->format('U.u'));
    }

    /**
     * @return iterable<array<string>>
     */
    public static function provideTime_fractions_precisions_are_respectedCases(): iterable
    {
        yield ['1613938511.017448'];

        yield ['1613938511.023691'];

        yield ['1613938511.018045'];

        yield ['1616074725.008455'];
    }

    #[Test()]
    #[DataProvider('provideType_conversion_does_not_cause_parsing_errorsCases')]
    public function type_conversion_does_not_cause_parsing_errors(float|int|string $issuedAt, string $timeFraction): void
    {
        $encoder = new JoseEncoder();
        $headers = $encoder->base64UrlEncode($encoder->jsonEncode(['typ' => 'JWT', 'alg' => 'none']));
        $claims = $encoder->base64UrlEncode($encoder->jsonEncode(['iat' => $issuedAt]));

        $config = Configuration::forSymmetricSigner(
            new KeyDumpSigner(),
            InMemory::plainText('private'),
        );
        $parsedToken = $config->parser()->parse($headers.'.'.$claims.'.cHJpdmF0ZQ');

        $this->assertInstanceOf(Plain::class, $parsedToken);
        $this->assertSame($timeFraction, $parsedToken->claims()->get('iat')->format('U.u'));
    }

    /**
     * @return iterable<array{0: float|int|string, 1: string}>
     */
    public static function provideType_conversion_does_not_cause_parsing_errorsCases(): iterable
    {
        yield [1_616_481_863.528_781_890_869_140_625, '1616481863.528782'];

        yield [1_616_497_608.051_040_9, '1616497608.051041'];

        yield [1_616_536_852.100_000_1, '1616536852.100000'];

        yield [1_616_457_346.387_813_1, '1616457346.387813'];

        yield [1_616_457_346.0, '1616457346.000000'];

        yield [1_616_457_346, '1616457346.000000'];

        yield ['1616481863.528781890869140625', '1616481863.528782'];

        yield ['1616497608.0510409', '1616497608.051041'];

        yield ['1616536852.1000001', '1616536852.100000'];

        yield ['1616457346.3878131', '1616457346.387813'];

        yield ['1616457346.0', '1616457346.000000'];

        yield ['1616457346', '1616457346.000000'];
    }
}
