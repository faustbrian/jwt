<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Cline\JWT\Contracts\BuilderInterface;
use Cline\JWT\Contracts\NowProviderInterface;
use Cline\JWT\Contracts\Signer\KeyInterface;
use Cline\JWT\Contracts\SignerInterface;
use Cline\JWT\Contracts\UnencryptedTokenInterface;
use Cline\JWT\IssueTokenRequest;
use Cline\JWT\JwtProfile;
use Cline\JWT\Signer\Hmac\Sha256;
use Cline\JWT\Signer\Key\InMemory;
use Cline\JWT\Validation\Constraint\IssuedBy;
use Cline\JWT\Validation\Constraint\PermittedFor;
use Cline\JWT\Validation\Constraint\SignedWith;
use Cline\JWT\Validation\Constraint\StrictValidAt;
use Tests\Exceptions\TestStubMethodWasCalled;

test('profile exposes configured collaborators and derived constraints', function (): void {
    $signer = new Sha256();
    $signingKey = InMemory::plainText('signing-secret');
    $verificationKey = InMemory::plainText('verify-secret');
    $profile = new JwtProfile(
        'api',
        $signer,
        $signingKey,
        $verificationKey,
        new DateInterval('PT15M'),
        new DateInterval('PT30S'),
        'https://issuer.test',
        ['web', 'admin'],
        ['kid' => 'key-1'],
        ['tenant' => 'acme'],
    );

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
    $validAt = $profile->validAtConstraint(
        new class() implements NowProviderInterface
        {
            public function now(): CarbonInterface
            {
                return CarbonImmutable::parse('2025-01-01 00:00:00');
            }
        },
    );

    expect($profile->name())->toBe('api')
        ->and($profile->signer())->toBe($signer)
        ->and($profile->signingKey())->toBe($signingKey)
        ->and($profile->verificationKey())->toBe($verificationKey)
        ->and($profile->signatureConstraint())->toEqual(
            new SignedWith($signer, $verificationKey),
        )
        ->and($validAt)->toBeInstanceOf(StrictValidAt::class)
        ->and($builder->claims['iss'])->toBe('https://issuer.test')
        ->and($builder->claims['tenant'])->toBe('acme')
        ->and($builder->headers['kid'])->toBe('key-1')
        ->and($builder->audiences)->toBe(['web', 'admin'])
        ->and($profile->validationConstraints())->toEqual([
            new IssuedBy('https://issuer.test'),
            new PermittedFor('web'),
            new PermittedFor('admin'),
        ]);
});

test('profile issue request and validation constraints omit empty issuer and audiences', function (): void {
    $profile = new JwtProfile(
        'minimal',
        new Sha256(),
        InMemory::plainText('signing-secret'),
        InMemory::plainText('verify-secret'),
    );

    expect($profile->issueRequest())->toEqual(
        new IssueTokenRequest(),
    )
        ->and($profile->validationConstraints())->toBe([]);
});
