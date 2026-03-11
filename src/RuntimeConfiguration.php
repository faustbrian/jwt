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
use Cline\JWT\Contracts\NowProviderInterface;
use Cline\JWT\Contracts\ParserInterface;
use Cline\JWT\Contracts\ValidatorInterface;
use Cline\JWT\Encoding\JoseEncoder;
use Cline\JWT\Support\DefaultBuilderFactory;
use Cline\JWT\Support\SystemNowProvider;
use Cline\JWT\Token\Parser;
use Cline\JWT\Validation\Validator;
use Closure;
use Illuminate\Container\Container;
use NoDiscard;

/**
 * Immutable bundle of the runtime collaborators used to issue and parse tokens.
 *
 * This type sits beneath {@see Configuration} and {@see JwtFacade} as the
 * package's lightweight runtime container. It captures the parser, builder
 * factory, validator, and clock provider that should travel together when a
 * consumer customizes one or more execution dependencies.
 *
 * The static factory prefers container bindings when the package is used inside
 * Laravel, but always falls back to framework-agnostic defaults so the core JWT
 * APIs remain usable in plain PHP environments.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class RuntimeConfiguration
{
    /**
     * Create a runtime bundle from explicit collaborators.
     */
    public function __construct(
        private ParserInterface $parser,
        private BuilderFactoryInterface $builderFactory,
        private ValidatorInterface $validator,
        private NowProviderInterface $nowProvider,
    ) {}

    /**
     * Build the default runtime configuration for the package.
     *
     * Resolution order is:
     * 1. Use an existing Laravel container binding when available.
     * 2. Otherwise instantiate the package's built-in implementation.
     *
     * The supplied encoder and decoder are threaded into fallback parser and
     * builder creation so callers can swap serialization behavior without
     * needing to rebuild the whole runtime stack themselves.
     */
    #[NoDiscard()]
    public static function defaults(
        EncoderInterface $encoder = new JoseEncoder(),
        DecoderInterface $decoder = new JoseEncoder(),
    ): self {
        $container = Container::getInstance();

        return new self(
            self::resolve($container, ParserInterface::class, static fn (): ParserInterface => new Parser($decoder)),
            self::resolve($container, BuilderFactoryInterface::class, static fn (): BuilderFactoryInterface => new DefaultBuilderFactory($encoder)),
            self::resolve($container, ValidatorInterface::class, static fn (): ValidatorInterface => new Validator()),
            self::resolve($container, NowProviderInterface::class, static fn (): NowProviderInterface => new SystemNowProvider()),
        );
    }

    /**
     * Return the parser responsible for decoding compact JWT strings.
     */
    public function parser(): ParserInterface
    {
        return $this->parser;
    }

    /**
     * Return a cloned runtime bundle with a different parser implementation.
     */
    #[NoDiscard()]
    public function withParser(ParserInterface $parser): self
    {
        return new self(
            $parser,
            $this->builderFactory,
            $this->validator,
            $this->nowProvider,
        );
    }

    /**
     * Return the factory used to create token builders for issuance.
     */
    public function builderFactory(): BuilderFactoryInterface
    {
        return $this->builderFactory;
    }

    /**
     * Return a cloned runtime bundle with a different builder factory.
     */
    #[NoDiscard()]
    public function withBuilderFactory(BuilderFactoryInterface $builderFactory): self
    {
        return new self(
            $this->parser,
            $builderFactory,
            $this->validator,
            $this->nowProvider,
        );
    }

    /**
     * Return the validator that enforces composed token constraints.
     */
    public function validator(): ValidatorInterface
    {
        return $this->validator;
    }

    /**
     * Return a cloned runtime bundle with a different validator.
     */
    #[NoDiscard()]
    public function withValidator(ValidatorInterface $validator): self
    {
        return new self(
            $this->parser,
            $this->builderFactory,
            $validator,
            $this->nowProvider,
        );
    }

    /**
     * Return the clock abstraction used for time-sensitive operations.
     */
    public function nowProvider(): NowProviderInterface
    {
        return $this->nowProvider;
    }

    /**
     * Return a cloned runtime bundle with a different clock abstraction.
     */
    #[NoDiscard()]
    public function withNowProvider(NowProviderInterface $nowProvider): self
    {
        return new self(
            $this->parser,
            $this->builderFactory,
            $this->validator,
            $nowProvider,
        );
    }

    /**
     * @template TDependency of object
     *
     * @param class-string<TDependency> $abstract
     * @param Closure(): TDependency    $fallback
     *
     * Resolve a runtime dependency from the container when possible.
     *
     * This keeps framework integration opt-in: the package can honor bindings
     * registered by the service provider, but it never requires a container to
     * exist in order to build a working runtime configuration.
     *
     * @return TDependency
     */
    private static function resolve(
        ?Container $container,
        string $abstract,
        Closure $fallback,
    ): object {
        if ($container instanceof Container && $container->bound($abstract)) {
            /** @var TDependency */
            return $container->make($abstract);
        }

        return $fallback();
    }
}
