<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT;

use Cline\JWT\Contracts\BuilderFactoryInterface;
use Cline\JWT\Contracts\DecoderInterface;
use Cline\JWT\Contracts\EncoderInterface;
use Cline\JWT\Contracts\JwtProfileRepositoryInterface;
use Cline\JWT\Contracts\NowProviderInterface;
use Cline\JWT\Contracts\ParserInterface;
use Cline\JWT\Contracts\ValidatorInterface;
use Cline\JWT\Encoding\JoseEncoder;
use Cline\JWT\Support\ConfigJwtProfileRepository;
use Cline\JWT\Support\DefaultBuilderFactory;
use Cline\JWT\Support\SystemNowProvider;
use Cline\JWT\Token\Parser;
use Cline\JWT\Validation\Validator;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use Override;

/**
 * Registers the JWT package runtime, facade, and profile repository with Laravel.
 *
 * The service provider wires the encoder/decoder pair, parser, builder factory,
 * validator, clock abstraction, runtime configuration, and profile repository into
 * the container so application code can depend on contracts instead of concrete
 * token primitives.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class JwtServiceProvider extends ServiceProvider
{
    /**
     * Register JWT services and merge package configuration into the host app.
     *
     * Singletons are used because the runtime collaborators are stateless or
     * configuration-backed and should be shared across the request lifecycle.
     */
    #[Override()]
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/jwt.php', 'jwt');
        $this->app->singleton(EncoderInterface::class, JoseEncoder::class);
        $this->app->singleton(DecoderInterface::class, JoseEncoder::class);
        $this->app->singleton(ParserInterface::class, static fn (Application $app): ParserInterface => new Parser(
            $app->make(DecoderInterface::class),
        ));
        $this->app->singleton(BuilderFactoryInterface::class, static fn (Application $app): BuilderFactoryInterface => new DefaultBuilderFactory(
            $app->make(EncoderInterface::class),
        ));
        $this->app->singleton(ValidatorInterface::class, Validator::class);
        $this->app->singleton(NowProviderInterface::class, SystemNowProvider::class);
        $this->app->singleton(RuntimeConfiguration::class, static fn (Application $app): RuntimeConfiguration => new RuntimeConfiguration(
            $app->make(ParserInterface::class),
            $app->make(BuilderFactoryInterface::class),
            $app->make(ValidatorInterface::class),
            $app->make(NowProviderInterface::class),
        ));
        $this->app->singleton(JwtProfileRepositoryInterface::class, static fn (Application $app): JwtProfileRepositoryInterface => new ConfigJwtProfileRepository(
            $app,
            $app->make(Repository::class),
        ));
        $this->app->singleton(JwtFacade::class, static fn (Application $app): JwtFacade => new JwtFacade(
            $app->make(RuntimeConfiguration::class),
            profiles: $app->make(JwtProfileRepositoryInterface::class),
        ));
        $this->app->alias(JwtFacade::class, 'jwt');
    }

    /**
     * Publish the package configuration for consumer customization.
     */
    public function boot(): void
    {
        $this->publishes([
            __DIR__.'/../config/jwt.php' => $this->app->configPath('jwt.php'),
        ], 'jwt-config');
    }
}
