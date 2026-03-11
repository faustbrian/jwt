<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Cline\JWT\Configuration;
use Cline\JWT\Contracts\BuilderFactoryInterface;
use Cline\JWT\Contracts\BuilderInterface;
use Cline\JWT\Contracts\ClaimsFormatterInterface;
use Cline\JWT\Contracts\EncoderInterface;
use Cline\JWT\Contracts\NowProviderInterface;
use Cline\JWT\Contracts\TokenInterface;
use Cline\JWT\Contracts\Validation\ConstraintInterface;
use Cline\JWT\Signer\Hmac\Sha256;
use Cline\JWT\Signer\Key\InMemory;
use Cline\JWT\Support\DefaultBuilderFactory;
use Tests\Exceptions\TestStubMethodWasCalled;

test('configuration exposes signer keys and now provider overrides', function (): void {
    $signer = new Sha256();
    $key = InMemory::plainText('0123456789abcdef0123456789abcdef');
    $constraint = new class() implements ConstraintInterface
    {
        public function assert(TokenInterface $token): void {}
    };
    $nowProvider = new class() implements NowProviderInterface
    {
        public function now(): CarbonInterface
        {
            return CarbonImmutable::parse('2025-01-01 00:00:00');
        }
    };
    $builderFactory = new class() implements BuilderFactoryInterface
    {
        public function create(ClaimsFormatterInterface $claimsFormatter): BuilderInterface
        {
            throw TestStubMethodWasCalled::notNeeded();
        }
    };

    $config = Configuration::forSymmetricSigner($signer, $key)
        ->withNowProvider($nowProvider)
        ->withBuilderFactory($builderFactory)
        ->withValidationConstraints($constraint);

    expect($config->signer())->toBe($signer)
        ->and($config->signingKey())->toBe($key)
        ->and($config->verificationKey())->toBe($key)
        ->and($config->nowProvider())->toBe($nowProvider)
        ->and($config->validationConstraints())->toBe([$constraint]);
});

test('configuration falls back to the default builder factory when none is provided', function (): void {
    $config = Configuration::forSymmetricSigner(
        new Sha256(),
        InMemory::plainText('0123456789abcdef0123456789abcdef'),
    );
    $method = new ReflectionMethod(Configuration::class, 'normalizeBuilderFactory');

    $factory = $method->invoke(
        $config,
        null,
        $this->createStub(EncoderInterface::class),
    );

    expect($factory)->toBeInstanceOf(DefaultBuilderFactory::class);
});
