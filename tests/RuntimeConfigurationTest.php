<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Carbon\CarbonImmutable;
use Cline\JWT\Contracts\BuilderFactoryInterface;
use Cline\JWT\Contracts\DecoderInterface;
use Cline\JWT\Contracts\EncoderInterface;
use Cline\JWT\Contracts\NowProviderInterface;
use Cline\JWT\Contracts\ParserInterface;
use Cline\JWT\Contracts\ValidatorInterface;
use Cline\JWT\RuntimeConfiguration;
use Cline\JWT\Support\DefaultBuilderFactory;
use Cline\JWT\Support\SystemNowProvider;
use Cline\JWT\Token\Parser;
use Cline\JWT\Validation\Validator;
use Illuminate\Container\Container;

beforeEach(function (): void {
    $this->previousContainer = Container::getInstance();

    Container::setInstance(
        new Container(),
    );
});

test('defaults use package fallbacks when container bindings are missing', function (): void {
    $encoder = $this->createStub(EncoderInterface::class);
    $decoder = $this->createStub(DecoderInterface::class);

    $runtime = RuntimeConfiguration::defaults($encoder, $decoder);

    expect($runtime->parser())->toEqual(
        new Parser($decoder),
    )
        ->and($runtime->builderFactory())->toEqual(
            new DefaultBuilderFactory($encoder),
        )
        ->and($runtime->validator())->toEqual(
            new Validator(),
        )
        ->and($runtime->nowProvider())->toEqual(
            new SystemNowProvider(),
        );
});

test('defaults resolve bound collaborators from the container', function (): void {
    $container = Container::getInstance();
    $parser = $this->createStub(ParserInterface::class);
    $builderFactory = $this->createStub(BuilderFactoryInterface::class);
    $validator = $this->createStub(ValidatorInterface::class);
    $nowProvider = $this->createStub(NowProviderInterface::class);

    $container->instance(ParserInterface::class, $parser);
    $container->instance(BuilderFactoryInterface::class, $builderFactory);
    $container->instance(ValidatorInterface::class, $validator);
    $container->instance(NowProviderInterface::class, $nowProvider);

    $runtime = RuntimeConfiguration::defaults();

    expect($runtime->parser())->toBe($parser)
        ->and($runtime->builderFactory())->toBe($builderFactory)
        ->and($runtime->validator())->toBe($validator)
        ->and($runtime->nowProvider())->toBe($nowProvider);
});

test('withers replace one collaborator while preserving the others', function (): void {
    $parser = $this->createStub(ParserInterface::class);
    $builderFactory = $this->createStub(BuilderFactoryInterface::class);
    $validator = $this->createStub(ValidatorInterface::class);
    $nowProvider = new class() implements NowProviderInterface
    {
        public function now(): CarbonImmutable
        {
            return CarbonImmutable::parse('2025-01-01 00:00:00');
        }
    };

    $runtime = new RuntimeConfiguration($parser, $builderFactory, $validator, $nowProvider);

    $newParser = $this->createStub(ParserInterface::class);
    $newBuilderFactory = $this->createStub(BuilderFactoryInterface::class);
    $newValidator = $this->createStub(ValidatorInterface::class);
    $newNowProvider = new class() implements NowProviderInterface
    {
        public function now(): CarbonImmutable
        {
            return CarbonImmutable::parse('2026-01-01 00:00:00');
        }
    };

    $parserRuntime = $runtime->withParser($newParser);
    $builderRuntime = $runtime->withBuilderFactory($newBuilderFactory);
    $validatorRuntime = $runtime->withValidator($newValidator);
    $nowRuntime = $runtime->withNowProvider($newNowProvider);

    expect($parserRuntime->parser())->toBe($newParser)
        ->and($parserRuntime->builderFactory())->toBe($builderFactory)
        ->and($parserRuntime->validator())->toBe($validator)
        ->and($parserRuntime->nowProvider())->toBe($nowProvider)
        ->and($builderRuntime->parser())->toBe($parser)
        ->and($builderRuntime->builderFactory())->toBe($newBuilderFactory)
        ->and($builderRuntime->validator())->toBe($validator)
        ->and($builderRuntime->nowProvider())->toBe($nowProvider)
        ->and($validatorRuntime->parser())->toBe($parser)
        ->and($validatorRuntime->builderFactory())->toBe($builderFactory)
        ->and($validatorRuntime->validator())->toBe($newValidator)
        ->and($validatorRuntime->nowProvider())->toBe($nowProvider)
        ->and($nowRuntime->parser())->toBe($parser)
        ->and($nowRuntime->builderFactory())->toBe($builderFactory)
        ->and($nowRuntime->validator())->toBe($validator)
        ->and($nowRuntime->nowProvider())->toBe($newNowProvider);
});

test('getters expose the configured collaborators', function (): void {
    $parser = $this->createStub(ParserInterface::class);
    $builderFactory = $this->createStub(BuilderFactoryInterface::class);
    $validator = $this->createStub(ValidatorInterface::class);
    $nowProvider = $this->createStub(NowProviderInterface::class);

    $runtime = new RuntimeConfiguration($parser, $builderFactory, $validator, $nowProvider);

    expect($runtime->parser())->toBe($parser)
        ->and($runtime->builderFactory())->toBe($builderFactory)
        ->and($runtime->validator())->toBe($validator)
        ->and($runtime->nowProvider())->toBe($nowProvider);
});

afterEach(function (): void {
    Container::setInstance($this->previousContainer);
});
