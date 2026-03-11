<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Support;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Cline\JWT\Contracts\BuilderInterface;
use Cline\JWT\Contracts\Signer\KeyInterface;
use Cline\JWT\Contracts\SignerInterface;
use Cline\JWT\Contracts\UnencryptedTokenInterface;
use Cline\JWT\Exceptions\InvalidProfileConfiguration;
use Cline\JWT\Exceptions\JwtProfileNotFound;
use Cline\JWT\JwtProfile;
use Cline\JWT\Signer\Hmac\Sha256;
use Cline\JWT\Signer\Key\InMemory;
use Cline\JWT\Support\ConfigJwtProfileRepository;
use DateInterval;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Tests\Exceptions\TestStubMethodWasCalled;

use function base64_encode;
use function expect;
use function realpath;
use function test;

test('default resolves the configured default profile name', function (): void {
    $container = $this->createStub(Container::class);
    $config = $this->createMock(Repository::class);
    $signer = new Sha256();

    $config->expects($this->exactly(2))->method('get')->willReturnMap([
        ['jwt.default', 'default', 'api'],
        ['jwt.profiles.api', null, [
            'signer' => $signer,
            'signing_key' => ['source' => 'secret'],
            'verification_key' => ['source' => 'secret'],
        ]],
    ]);

    $profile = new ConfigJwtProfileRepository($container, $config)->default();

    expect($profile)->toBeInstanceOf(JwtProfile::class)
        ->and($profile->name())->toBe('api')
        ->and($profile->signer())->toBe($signer)
        ->and($profile->signingKey()->contents())->toBe('secret')
        ->and($profile->verificationKey()->contents())->toBe('secret');
});

test('get resolves a named profile from instances and normalized config values', function (): void {
    $container = $this->createStub(Container::class);
    $config = $this->createMock(Repository::class);
    $signer = new Sha256();

    $config->expects($this->exactly(1))->method('get')->willReturnMap([
        ['jwt.profiles.api', null, [
            'signer' => $signer,
            'signing_key' => ['loader' => 'plain', 'source' => 'signing-secret', 'passphrase' => 'sign'],
            'verification_key' => ['loader' => 'base64', 'source' => base64_encode('verify-secret'), 'passphrase' => 'verify'],
            'ttl' => 'PT15M',
            'leeway' => new DateInterval('PT30S'),
            'issuer' => 'https://issuer.test',
            'audiences' => ['web', 'admin'],
            'headers' => ['kid' => 'key-1'],
            'claims' => ['tenant' => 'acme'],
        ]],
    ]);

    $profile = new ConfigJwtProfileRepository($container, $config)->get('api');
    $request = $profile->issueRequest();
    $builder = new class() implements BuilderInterface
    {
        public array $headers = [];

        public array $claims = [];

        public array $audiences = [];

        public function permittedFor(string ...$audiences): self
        {
            $this->audiences = $audiences;

            return $this;
        }

        public function expiresAt(CarbonInterface $expiration): self
        {
            $this->claims['exp'] = $expiration;

            return $this;
        }

        public function identifiedBy(string $id): self
        {
            $this->claims['jti'] = $id;

            return $this;
        }

        public function issuedAt(CarbonInterface $issuedAt): self
        {
            $this->claims['iat'] = $issuedAt;

            return $this;
        }

        public function issuedBy(string $issuer): self
        {
            $this->claims['iss'] = $issuer;

            return $this;
        }

        public function canOnlyBeUsedAfter(CarbonInterface $notBefore): self
        {
            $this->claims['nbf'] = $notBefore;

            return $this;
        }

        public function relatedTo(string $subject): self
        {
            $this->claims['sub'] = $subject;

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
            throw TestStubMethodWasCalled::notNeeded();
        }
    };

    $request->applyTo($builder, CarbonImmutable::parse('2025-01-01 00:00:00'));

    expect($profile->name())->toBe('api')
        ->and($profile->signer())->toBe($signer)
        ->and($profile->signingKey()->contents())->toBe('signing-secret')
        ->and($profile->signingKey()->passphrase())->toBe('sign')
        ->and($profile->verificationKey()->contents())->toBe('verify-secret')
        ->and($profile->verificationKey()->passphrase())->toBe('verify')
        ->and($builder->claims['iss'])->toBe('https://issuer.test')
        ->and($builder->claims['tenant'])->toBe('acme')
        ->and($builder->headers['kid'])->toBe('key-1')
        ->and($builder->audiences)->toBe(['web', 'admin']);
});

test('get resolves signer class names from the container', function (): void {
    $container = $this->createMock(Container::class);
    $config = $this->createMock(Repository::class);
    $signer = new Sha256();

    $config->expects($this->exactly(1))->method('get')->willReturnMap([
        ['jwt.profiles.api', null, [
            'signer' => Sha256::class,
            'signing_key' => ['source' => 'signing-secret'],
            'verification_key' => ['source' => 'verify-secret'],
        ]],
    ]);

    $container->expects($this->once())
        ->method('make')
        ->with(Sha256::class)
        ->willReturn($signer);

    $profile = new ConfigJwtProfileRepository($container, $config)->get('api');

    expect($profile->signer())->toBe($signer);
});

test('get reuses the default profile name when null is provided', function (): void {
    $container = $this->createStub(Container::class);
    $config = $this->createMock(Repository::class);
    $signer = new Sha256();

    $config->expects($this->exactly(3))->method('get')->willReturnMap([
        ['jwt.default', 'default', 'api'],
        ['jwt.profiles.api', null, [
            'signer' => $signer,
            'signing_key' => ['source' => 'secret'],
            'verification_key' => ['source' => 'secret'],
        ]],
    ]);

    $profile = new ConfigJwtProfileRepository($container, $config)->get();

    expect($profile->name())->toBe('api');
});

test('get throws when a named profile does not exist', function (): void {
    $container = $this->createStub(Container::class);
    $config = $this->createMock(Repository::class);
    $config->method('get')->willReturn(null);

    expect(fn (): JwtProfile => new ConfigJwtProfileRepository($container, $config)->get('missing'))
        ->toThrow(JwtProfileNotFound::class, 'JWT profile "missing" is not defined');
});

test('invalid profile configurations raise descriptive exceptions', function (array $profile, string $message): void {
    $container = $this->createStub(Container::class);
    $config = $this->createMock(Repository::class);
    $config->expects($this->exactly(1))->method('get')->willReturnMap([
        ['jwt.profiles.api', null, $profile],
    ]);

    expect(fn (): JwtProfile => new ConfigJwtProfileRepository($container, $config)->get('api'))
        ->toThrow(InvalidProfileConfiguration::class, 'JWT profile "api" is invalid: '.$message);
})->with([
    'missing signer' => [[
        'signing_key' => ['source' => 'secret'],
        'verification_key' => ['source' => 'secret'],
    ], 'a valid signer must be configured'],
    'invalid signing key type' => [[
        'signer' => new Sha256(),
        'signing_key' => 'secret',
        'verification_key' => ['source' => 'secret'],
    ], 'signing_key must be a key definition array'],
    'invalid loader config' => [[
        'signer' => new Sha256(),
        'signing_key' => ['loader' => [], 'source' => 'secret'],
        'verification_key' => ['source' => 'secret'],
    ], 'signing_key loader configuration is invalid'],
    'missing source' => [[
        'signer' => new Sha256(),
        'signing_key' => ['loader' => 'plain'],
        'verification_key' => ['source' => 'secret'],
    ], 'signing_key source must be a non-empty string'],
    'unknown loader' => [[
        'signer' => new Sha256(),
        'signing_key' => ['loader' => 'vault', 'source' => 'secret'],
        'verification_key' => ['source' => 'secret'],
    ], 'signing_key loader must be one of [plain, base64, file]'],
    'invalid ttl type' => [[
        'signer' => new Sha256(),
        'signing_key' => ['source' => 'secret'],
        'verification_key' => ['source' => 'secret'],
        'ttl' => 5,
    ], 'ttl must be an ISO-8601 interval string'],
    'invalid leeway type' => [[
        'signer' => new Sha256(),
        'signing_key' => ['source' => 'secret'],
        'verification_key' => ['source' => 'secret'],
        'leeway' => 5,
    ], 'leeway must be an ISO-8601 interval string'],
    'invalid issuer type' => [[
        'signer' => new Sha256(),
        'signing_key' => ['source' => 'secret'],
        'verification_key' => ['source' => 'secret'],
        'issuer' => ['nope'],
    ], 'issuer must be a string or null'],
    'invalid audiences shape' => [[
        'signer' => new Sha256(),
        'signing_key' => ['source' => 'secret'],
        'verification_key' => ['source' => 'secret'],
        'audiences' => 'web',
    ], 'audiences must be a list of strings'],
    'invalid audience item' => [[
        'signer' => new Sha256(),
        'signing_key' => ['source' => 'secret'],
        'verification_key' => ['source' => 'secret'],
        'audiences' => ['web', ''],
    ], 'audiences must contain only non-empty strings'],
    'invalid headers shape' => [[
        'signer' => new Sha256(),
        'signing_key' => ['source' => 'secret'],
        'verification_key' => ['source' => 'secret'],
        'headers' => ['kid'],
    ], 'headers must be an associative array'],
    'invalid header key' => [[
        'signer' => new Sha256(),
        'signing_key' => ['source' => 'secret'],
        'verification_key' => ['source' => 'secret'],
        'headers' => ['' => 'kid'],
    ], 'headers keys must be non-empty strings'],
    'invalid claims shape' => [[
        'signer' => new Sha256(),
        'signing_key' => ['source' => 'secret'],
        'verification_key' => ['source' => 'secret'],
        'claims' => ['tenant'],
    ], 'claims must be an associative array'],
    'invalid claim key' => [[
        'signer' => new Sha256(),
        'signing_key' => ['source' => 'secret'],
        'verification_key' => ['source' => 'secret'],
        'claims' => ['' => 'tenant'],
    ], 'claims keys must be non-empty strings'],
]);

test('file key loader reads key material from disk', function (): void {
    $container = $this->createStub(Container::class);
    $config = $this->createMock(Repository::class);
    $path = realpath(__DIR__.'/../Signer/Key/test.pem');

    expect($path)->not->toBeFalse();

    $config->expects($this->exactly(1))->method('get')->willReturnMap([
        ['jwt.profiles.api', null, [
            'signer' => new Sha256(),
            'signing_key' => ['loader' => 'file', 'source' => $path, 'passphrase' => 'test'],
            'verification_key' => InMemory::plainText('verify-secret'),
        ]],
    ]);

    $profile = new ConfigJwtProfileRepository($container, $config)->get('api');

    expect($profile->signingKey()->contents())->toBe('testing')
        ->and($profile->signingKey()->passphrase())->toBe('test');
});
