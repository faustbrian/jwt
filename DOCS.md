# JWT Documentation

## Overview

`cline/jwt` is a Laravel-first package for issuing and validating JSON
Web Tokens and JSON Web Signatures. The intended application surface is
the container-bound [JwtFacade](src/JwtFacade.php) and the Laravel facade
at [JWT](src/Facades/JWT.php), backed by named profiles from
[config/jwt.php](config/jwt.php).

The package still exposes lower-level primitives such as
[IssueTokenRequest](src/IssueTokenRequest.php),
[RuntimeConfiguration](src/RuntimeConfiguration.php), and the signer/key
types when you need more control.

## Requirements

- PHP 8.5+
- `ext-openssl`
- `ext-sodium`
- Laravel container support via `illuminate/container`
- Laravel support helpers via `illuminate/support`

## Installation

Install the package with Composer:

```bash
composer require cline/jwt
```

Laravel package discovery registers:

- [JwtServiceProvider](src/JwtServiceProvider.php)
- The `JWT` facade alias

If you want to publish the package config:

```bash
php artisan vendor:publish --tag=jwt-config
```

## Configuration

The package publishes [config/jwt.php](config/jwt.php). The main entry
points are:

- `default`: the profile name used by `JWT::issueFor()` and
  `JWT::parseFor()` when no profile is passed
- `profiles`: a keyed map of named JWT profiles

Each profile supports:

- `signer`: a signer class name or signer instance
- `signing_key`: key definition for token issuance
- `verification_key`: key definition for validation
- `ttl`: ISO-8601 `DateInterval` string used as the default expiry
- `leeway`: ISO-8601 `DateInterval` string for validation clock skew
- `issuer`: default `iss` claim
- `audiences`: default `aud` values
- `headers`: default JWT header values
- `claims`: default custom claim values

Key definitions use this structure:

```php
[
    'loader' => 'plain', // plain | base64 | file
    'source' => env('JWT_SIGNING_KEY'),
    'passphrase' => env('JWT_SIGNING_KEY_PASSPHRASE', ''),
]
```

Example config with separate access and refresh profiles:

```php
use Cline\JWT\Signer\Hmac\Sha256;

return [
    'default' => 'access',

    'profiles' => [
        'access' => [
            'signer' => Sha256::class,
            'signing_key' => [
                'loader' => 'base64',
                'source' => env('JWT_ACCESS_SIGNING_KEY'),
            ],
            'verification_key' => [
                'loader' => 'base64',
                'source' => env('JWT_ACCESS_VERIFICATION_KEY'),
            ],
            'ttl' => 'PT15M',
            'leeway' => 'PT30S',
            'issuer' => env('APP_URL'),
            'audiences' => ['web'],
            'headers' => ['kid' => 'access-v1'],
            'claims' => ['token_type' => 'access'],
        ],
        'refresh' => [
            'signer' => Sha256::class,
            'signing_key' => [
                'loader' => 'base64',
                'source' => env('JWT_REFRESH_SIGNING_KEY'),
            ],
            'verification_key' => [
                'loader' => 'base64',
                'source' => env('JWT_REFRESH_VERIFICATION_KEY'),
            ],
            'ttl' => 'P30D',
            'issuer' => env('APP_URL'),
            'audiences' => ['auth'],
            'claims' => ['token_type' => 'refresh'],
        ],
    ],
];
```

## Basic Usage

### Issue a token with the default profile

```php
use Cline\JWT\IssueTokenRequest;
use Cline\JWT\Facades\JWT;

$token = JWT::issueFor(
    request: (new IssueTokenRequest())
        ->relatedTo((string) $user->getKey())
        ->withClaim('email', $user->email),
);
```

### Parse and validate with the default profile

```php
use Cline\JWT\Facades\JWT;

$parsed = JWT::parseFor($token->toString());

$subject = $parsed->claims()->subject();
$issuer = $parsed->claims()->issuer();
```

### Use a named profile

```php
use Cline\JWT\IssueTokenRequest;
use Cline\JWT\Facades\JWT;

$refreshToken = JWT::issueFor(
    'refresh',
    (new IssueTokenRequest())->relatedTo((string) $user->getKey()),
);

$parsedRefreshToken = JWT::parseFor($refreshToken->toString(), 'refresh');
```

### Resolve profile metadata directly

```php
use Cline\JWT\JwtFacade;

$profile = app(JwtFacade::class)->profile('access');

$name = $profile->name();
$signer = $profile->signer();
```

## IssueTokenRequest

[IssueTokenRequest](src/IssueTokenRequest.php) is the fluent input object
used when issuing tokens. It supports:

- `identifiedBy()`
- `issuedBy()`
- `relatedTo()`
- `permittedFor()`
- `issuedAt()`
- `canOnlyBeUsedAfter()`
- `expiresAt()`
- `expiresAfter()`
- `withHeader()`
- `withClaim()`

Profile defaults are merged with the request passed to `issueFor()`. The
request you supply wins for scalar and time values, while headers, claims,
and audiences are combined.

## Validation Flow

`JWT::parseFor()` builds validation from the selected profile:

- signature validation via the configured signer and verification key
- time validation via the configured `leeway`
- issuer validation when `issuer` is configured
- audience validation for every configured audience

You can append extra constraints when needed:

```php
use Cline\JWT\Facades\JWT;
use Cline\JWT\Validation\Constraint\HasClaimWithValue;

$token = JWT::parseFor(
    $jwt,
    'access',
    new HasClaimWithValue('tenant', 'acme'),
);
```

## Lower-Level API

If you do not want profile-based issuance, you can still use the lower
level API directly:

```php
use Cline\JWT\IssueTokenRequest;
use Cline\JWT\JwtFacade;
use Cline\JWT\Signer\Hmac\Sha256;
use Cline\JWT\Signer\Key\InMemory;
use Cline\JWT\Validation\Constraint\SignedWith;
use Cline\JWT\Validation\Constraint\StrictValidAt;

$facade = app(JwtFacade::class);
$signer = new Sha256();
$key = InMemory::base64Encoded(env('JWT_SIGNING_KEY'));

$token = $facade->issue(
    $signer,
    $key,
    (new IssueTokenRequest())->issuedBy(config('app.url')),
);

$parsed = $facade->parse(
    $token->toString(),
    new SignedWith($signer, $key),
    new StrictValidAt(),
);
```

## Container Bindings

[JwtServiceProvider](src/JwtServiceProvider.php) registers:

- `Cline\JWT\Contracts\EncoderInterface`
- `Cline\JWT\Contracts\DecoderInterface`
- `Cline\JWT\Contracts\ParserInterface`
- `Cline\JWT\Contracts\BuilderFactoryInterface`
- `Cline\JWT\Contracts\ValidatorInterface`
- `Cline\JWT\Contracts\NowProviderInterface`
- `Cline\JWT\Contracts\JwtProfileRepositoryInterface`
- [RuntimeConfiguration](src/RuntimeConfiguration.php)
- [JwtFacade](src/JwtFacade.php)
- the `jwt` container alias
- the `JWT` facade alias

## Exceptions

Profile-driven Laravel usage will most commonly surface:

- [JwtProfileNotFound](src/Exceptions/JwtProfileNotFound.php) when a
  requested profile name is missing
- [InvalidProfileConfiguration](src/Exceptions/InvalidProfileConfiguration.php)
  when a configured signer, key, interval, or value shape is invalid

Validation failures continue to raise the existing constraint and token
exceptions from [src/Exceptions](src/Exceptions).

## Testing and Quality

The package verification commands are:

```bash
vendor/bin/phpunit
vendor/bin/phpstan
vendor/bin/ecs check
vendor/bin/rector process --dry-run
```

Laravel integration behavior is covered in
[JwtServiceProviderTest.php](tests/Laravel/JwtServiceProviderTest.php).

## Release Notes

The current architecture is intentionally Laravel-oriented:

- use profiles as the default integration surface
- use the facade or container-bound `JwtFacade` in application code
- drop to lower-level APIs only when profile composition is insufficient
