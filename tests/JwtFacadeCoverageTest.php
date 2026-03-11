<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Cline\JWT\Contracts\BuilderFactoryInterface;
use Cline\JWT\Contracts\BuilderInterface;
use Cline\JWT\Contracts\ClaimsFormatterInterface;
use Cline\JWT\Contracts\JwtProfileRepositoryInterface;
use Cline\JWT\Contracts\NowProviderInterface;
use Cline\JWT\Contracts\ParserInterface;
use Cline\JWT\Contracts\Signer\KeyInterface;
use Cline\JWT\Contracts\SignerInterface;
use Cline\JWT\Contracts\TokenInterface;
use Cline\JWT\Contracts\UnencryptedTokenInterface;
use Cline\JWT\Contracts\Validation\ConstraintInterface;
use Cline\JWT\Contracts\ValidatorInterface;
use Cline\JWT\Encoding\ChainedFormatter;
use Cline\JWT\IssueTokenRequest;
use Cline\JWT\JwtFacade;
use Cline\JWT\JwtProfile;
use Cline\JWT\RuntimeConfiguration;
use Cline\JWT\Signer\Hmac\Sha256;
use Cline\JWT\Signer\Key\InMemory;
use Cline\JWT\Token\Plain;
use Cline\JWT\Validation\Constraint\IssuedBy;
use Cline\JWT\Validation\Constraint\SignedWith;
use Cline\JWT\Validation\Constraint\StrictValidAt;
use Illuminate\Container\Container;

beforeEach(function (): void {
    $this->previousContainer = Container::getInstance();
});

afterEach(function (): void {
    Container::setInstance($this->previousContainer);
});

test('profile raises when repository is not configured', function (): void {
    Container::setInstance(
        new Container(),
    );

    expect(fn (): JwtProfile => new JwtFacade()->profile())
        ->toThrow(RuntimeException::class, 'JWT profile repository is not configured');
});

test('constructor with runtime configuration honors explicit repository', function (): void {
    $profile = jwtFacadeProfile('api');
    $repository = jwtFacadeRepository($profile);
    $facade = new JwtFacade(jwtFacadeRuntimeConfigurationStub(), profiles: $repository);

    expect($facade->profile('api'))->toBe($profile);
});

test('constructor resolves repository from container when not provided', function (): void {
    $profile = jwtFacadeProfile('api');
    $repository = jwtFacadeRepository($profile);
    $container = new Container();
    $container->instance(JwtProfileRepositoryInterface::class, $repository);
    Container::setInstance($container);

    $facade = new JwtFacade(jwtFacadeRuntimeConfigurationStub());

    expect($facade->profile('api'))->toBe($profile);
});

test('constructor applies explicit runtime collaborators to issue and parse', function (): void {
    $now = CarbonImmutable::parse('2024-02-03 04:05:06');
    $token = jwtFacadeToken($now);
    $recordingParser = jwtFacadeParserStub($token);
    $recordingValidator = jwtFacadeValidatorRecorder();
    $recordingBuilderFactory = jwtFacadeBuilderFactoryStub($token, $now);
    $nowProvider = jwtFacadeNowProvider($now);
    $facade = new JwtFacade($recordingParser, $recordingBuilderFactory, $recordingValidator, $nowProvider);

    $issued = $facade->issue(
        new Sha256(),
        InMemory::plainText('secret'),
    );
    $parsed = $facade->parse(
        'jwt',
        new SignedWith(
            new Sha256(),
            InMemory::plainText('secret'),
        ),
        new StrictValidAt(),
    );

    expect($issued)->toBe($token)
        ->and($parsed)->toBe($token)
        ->and($recordingBuilderFactory->lastFormatter)->toBeInstanceOf(ChainedFormatter::class)
        ->and($recordingValidator->assertedToken)->toBe($token)
        ->and($recordingValidator->constraints)->toHaveCount(2);
});

test('issue for and parse for use profile derived defaults and extra constraints', function (): void {
    $now = CarbonImmutable::parse('2024-03-04 05:06:07');
    $token = jwtFacadeToken($now);
    $profile = jwtFacadeProfile('api');
    $repository = jwtFacadeRepository($profile);
    $parser = jwtFacadeParserStub($token);
    $validator = jwtFacadeValidatorRecorder();
    $builderFactory = jwtFacadeBuilderFactoryStub($token, $now);
    $facade = new JwtFacade(
        new RuntimeConfiguration($parser, $builderFactory, $validator, jwtFacadeNowProvider($now)),
        profiles: $repository,
    );

    $issued = $facade->issueFor('api', new IssueTokenRequest()->identifiedBy('override')->withClaim('scope', 'write'));
    $parsed = $facade->parseFor('jwt', 'api', new IssuedBy('extra'));

    expect($issued)->toBe($token)
        ->and($parsed)->toBe($token)
        ->and($builderFactory->capturedBuilder?->identifier)->toBe('override')
        ->and($builderFactory->capturedBuilder?->issuer)->toBe('https://issuer.test')
        ->and($builderFactory->capturedBuilder?->claims)->toBe(['tenant' => 'acme', 'scope' => 'write'])
        ->and($validator->constraints)->toHaveCount(5);
});

function jwtFacadeRuntimeConfigurationStub(): RuntimeConfiguration
{
    $now = CarbonImmutable::parse('2024-01-01 00:00:00');

    return new RuntimeConfiguration(
        jwtFacadeParserStub(jwtFacadeToken($now)),
        jwtFacadeBuilderFactoryStub(jwtFacadeToken($now), $now),
        jwtFacadeValidatorRecorder(),
        jwtFacadeNowProvider($now),
    );
}

function jwtFacadeProfile(string $name): JwtProfile
{
    return new JwtProfile(
        $name,
        new Sha256(),
        InMemory::plainText(jwtFacadeSecret()),
        InMemory::plainText(jwtFacadeSecret()),
        new DateInterval('PT5M'),
        new DateInterval('PT30S'),
        'https://issuer.test',
        ['web'],
        ['kid' => 'key-1'],
        ['tenant' => 'acme'],
    );
}

function jwtFacadeRepository(JwtProfile $profile): JwtProfileRepositoryInterface
{
    return new readonly class($profile) implements JwtProfileRepositoryInterface
    {
        public function __construct(
            private JwtProfile $profile,
        ) {}

        public function default(): JwtProfile
        {
            return $this->profile;
        }

        public function get(?string $name = null): JwtProfile
        {
            return $this->profile;
        }
    };
}

function jwtFacadeNowProvider(CarbonImmutable $now): NowProviderInterface
{
    return new readonly class($now) implements NowProviderInterface
    {
        public function __construct(
            private CarbonImmutable $now,
        ) {}

        public function now(): CarbonInterface
        {
            return $this->now;
        }
    };
}

function jwtFacadeToken(CarbonImmutable $now): Plain
{
    return new JwtFacade()->issue(
        new Sha256(),
        InMemory::plainText(jwtFacadeSecret()),
        new IssueTokenRequest()->issuedBy('https://issuer.test')->expiresAt($now->addMinutes(5)),
    );
}

function jwtFacadeSecret(): string
{
    return '0123456789abcdef0123456789abcdef';
}

function jwtFacadeParserStub(UnencryptedTokenInterface|TokenInterface $token): ParserInterface
{
    return new readonly class($token) implements ParserInterface
    {
        public function __construct(
            private UnencryptedTokenInterface|TokenInterface $token,
        ) {}

        public function parse(string $jwt): TokenInterface
        {
            return $this->token;
        }
    };
}

function jwtFacadeValidatorRecorder(): ValidatorInterface
{
    return new class() implements ValidatorInterface
    {
        public ?TokenInterface $assertedToken = null;

        /** @var array<int, ConstraintInterface> */
        public array $constraints = [];

        public function assert(TokenInterface $token, ConstraintInterface ...$constraints): void
        {
            $this->assertedToken = $token;
            $this->constraints = $constraints;
        }

        public function validate(TokenInterface $token, ConstraintInterface ...$constraints): bool
        {
            return true;
        }
    };
}

function jwtFacadeBuilderFactoryStub(Plain $token, CarbonImmutable $now): BuilderFactoryInterface
{
    return new class($token, $now) implements BuilderFactoryInterface
    {
        public ?ClaimsFormatterInterface $lastFormatter = null;

        public ?object $capturedBuilder = null;

        public function __construct(
            private readonly Plain $token,
            private readonly CarbonImmutable $now,
        ) {}

        public function create(ClaimsFormatterInterface $claimsFormatter): BuilderInterface
        {
            $this->lastFormatter = $claimsFormatter;

            return $this->capturedBuilder = new class($this->token, $this->now) implements BuilderInterface
            {
                public ?CarbonImmutable $issuedAt = null;

                public ?CarbonImmutable $notBefore = null;

                public ?CarbonImmutable $expiresAt = null;

                public ?string $identifier = null;

                public ?string $issuer = null;

                public ?string $subject = null;

                /** @var array<int, string> */
                public array $audiences = [];

                /** @var array<string, mixed> */
                public array $headers = [];

                /** @var array<string, mixed> */
                public array $claims = [];

                public function __construct(
                    private readonly Plain $token,
                ) {}

                public function permittedFor(string ...$audiences): self
                {
                    $this->audiences = $audiences;

                    return $this;
                }

                public function expiresAt(CarbonInterface $expiration): self
                {
                    $this->expiresAt = CarbonImmutable::instance($expiration);

                    return $this;
                }

                public function identifiedBy(string $id): self
                {
                    $this->identifier = $id;

                    return $this;
                }

                public function issuedAt(CarbonInterface $issuedAt): self
                {
                    $this->issuedAt = CarbonImmutable::instance($issuedAt);

                    return $this;
                }

                public function issuedBy(string $issuer): self
                {
                    $this->issuer = $issuer;

                    return $this;
                }

                public function canOnlyBeUsedAfter(CarbonInterface $notBefore): self
                {
                    $this->notBefore = CarbonImmutable::instance($notBefore);

                    return $this;
                }

                public function relatedTo(string $subject): self
                {
                    $this->subject = $subject;

                    return $this;
                }

                public function withHeader(string $name, mixed $value): self
                {
                    $this->headers[$name] = $value;

                    return $this;
                }

                public function withClaim(string $name, mixed $value): self
                {
                    $this->claims[$name] = $value;

                    return $this;
                }

                public function getToken(SignerInterface $signer, KeyInterface $key): UnencryptedTokenInterface
                {
                    return $this->token;
                }
            };
        }
    };
}
