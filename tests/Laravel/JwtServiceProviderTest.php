<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Laravel;

use Carbon\CarbonImmutable;
use Cline\JWT\Contracts\BuilderFactoryInterface;
use Cline\JWT\Contracts\DecoderInterface;
use Cline\JWT\Contracts\EncoderInterface;
use Cline\JWT\Contracts\JwtProfileRepositoryInterface;
use Cline\JWT\Contracts\NowProviderInterface;
use Cline\JWT\Contracts\ParserInterface;
use Cline\JWT\Contracts\ValidatorInterface;
use Cline\JWT\Exceptions\JwtProfileNotFound;
use Cline\JWT\Facades\JWT;
use Cline\JWT\IssueTokenRequest;
use Cline\JWT\JwtFacade;
use Cline\JWT\JwtProfile;
use Cline\JWT\JwtServiceProvider;
use Cline\JWT\RuntimeConfiguration;
use Cline\JWT\Signer\Hmac\Sha256;
use Cline\JWT\Signer\Key\InMemory;
use Cline\JWT\Validation\Constraint\SignedWith;
use Cline\JWT\Validation\Constraint\StrictValidAt;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\Facades\Facade;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\After;
use PHPUnit\Framework\Attributes\Test;

/**
 * @author Brian Faust <brian@cline.sh>
 * @internal
 */
final class JwtServiceProviderTest extends TestCase
{
    #[After()]
    public function clearTestNow(): void
    {
        CarbonImmutable::setTestNow();
    }

    #[Test()]
    public function it_registers_the_runtime_and_primary_entrypoint(): void
    {
        $this->assertInstanceOf(EncoderInterface::class, $this->app->make(EncoderInterface::class));
        $this->assertInstanceOf(DecoderInterface::class, $this->app->make(DecoderInterface::class));
        $this->assertInstanceOf(ParserInterface::class, $this->app->make(ParserInterface::class));
        $this->assertInstanceOf(BuilderFactoryInterface::class, $this->app->make(BuilderFactoryInterface::class));
        $this->assertInstanceOf(ValidatorInterface::class, $this->app->make(ValidatorInterface::class));
        $this->assertInstanceOf(NowProviderInterface::class, $this->app->make(NowProviderInterface::class));
        $this->assertInstanceOf(JwtProfileRepositoryInterface::class, $this->app->make(JwtProfileRepositoryInterface::class));
        $this->assertInstanceOf(RuntimeConfiguration::class, $this->app->make(RuntimeConfiguration::class));
        $this->assertInstanceOf(JwtFacade::class, $this->app->make(JwtFacade::class));
        $this->assertSame($this->app->make(JwtFacade::class), $this->app->make('jwt'));
    }

    #[Test()]
    public function laravel_facade_uses_the_bound_jwt_service(): void
    {
        Facade::setFacadeApplication($this->app);
        CarbonImmutable::setTestNow(CarbonImmutable::parse('2024-01-01 00:00:00'));

        $signer = new Sha256();
        $key = InMemory::base64Encoded('qOIXmZRqZKY80qg0BjtCrskM6OK7gPOea8mz1H7h/dE=');
        $token = JWT::issue(
            $signer,
            $key,
            new IssueTokenRequest()->issuedBy('laravel.test'),
        );

        $parsed = JWT::parse(
            $token->toString(),
            new SignedWith($signer, $key),
            new StrictValidAt(),
        );

        $this->assertSame('laravel.test', $parsed->claims()->issuer());
    }

    #[Test()]
    public function profile_based_api_uses_configured_defaults(): void
    {
        Facade::setFacadeApplication($this->app);
        CarbonImmutable::setTestNow(CarbonImmutable::parse('2024-01-01 00:00:00'));

        $token = JWT::issueFor(request: new IssueTokenRequest()->relatedTo('user-1'));
        $parsed = JWT::parseFor($token->toString());

        $this->assertSame('https://api.example.test', $parsed->claims()->issuer());
        $this->assertTrue($parsed->isPermittedFor('web'));
        $this->assertSame('acme', $parsed->claims()->get('tenant'));
        $this->assertSame('primary', $parsed->headers()->keyId());
        $this->assertSame('user-1', $parsed->claims()->subject());
    }

    #[Test()]
    public function named_profiles_can_be_resolved_from_the_jwt_service(): void
    {
        $profile = $this->app->make(JwtFacade::class)->profile('refresh');

        $this->assertInstanceOf(JwtProfile::class, $profile);
        $this->assertSame('refresh', $profile->name());
    }

    #[Test()]
    public function unknown_profiles_raise_a_domain_error(): void
    {
        $this->expectException(JwtProfileNotFound::class);

        (void) $this->app->make(JwtFacade::class)->profile('missing');
    }

    protected function getEnvironmentSetUp($app): void
    {
        $config = $app->make(Repository::class);
        $config->set('jwt.default', 'access');
        $config->set('jwt.profiles.access', [
            'signer' => Sha256::class,
            'signing_key' => [
                'loader' => 'base64',
                'source' => 'qOIXmZRqZKY80qg0BjtCrskM6OK7gPOea8mz1H7h/dE=',
            ],
            'verification_key' => [
                'loader' => 'base64',
                'source' => 'qOIXmZRqZKY80qg0BjtCrskM6OK7gPOea8mz1H7h/dE=',
            ],
            'ttl' => 'PT10M',
            'leeway' => 'PT30S',
            'issuer' => 'https://api.example.test',
            'audiences' => ['web'],
            'headers' => ['kid' => 'primary'],
            'claims' => ['tenant' => 'acme'],
        ]);
        $config->set('jwt.profiles.refresh', [
            'signer' => Sha256::class,
            'signing_key' => [
                'loader' => 'base64',
                'source' => 'qOIXmZRqZKY80qg0BjtCrskM6OK7gPOea8mz1H7h/dE=',
            ],
            'verification_key' => [
                'loader' => 'base64',
                'source' => 'qOIXmZRqZKY80qg0BjtCrskM6OK7gPOea8mz1H7h/dE=',
            ],
            'ttl' => 'PT1H',
            'issuer' => 'https://auth.example.test',
            'audiences' => ['mobile'],
            'headers' => [],
            'claims' => [],
        ]);
    }

    /**
     * @param  mixed               $app
     * @return array<class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [JwtServiceProvider::class];
    }
}
