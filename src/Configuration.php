<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT;

use Cline\JWT\Contracts\BuilderFactoryInterface;
use Cline\JWT\Contracts\BuilderInterface;
use Cline\JWT\Contracts\ClaimsFormatterInterface;
use Cline\JWT\Contracts\DecoderInterface;
use Cline\JWT\Contracts\EncoderInterface;
use Cline\JWT\Contracts\NowProviderInterface;
use Cline\JWT\Contracts\ParserInterface;
use Cline\JWT\Contracts\Signer\KeyInterface;
use Cline\JWT\Contracts\SignerInterface;
use Cline\JWT\Contracts\Validation\ConstraintInterface;
use Cline\JWT\Contracts\ValidatorInterface;
use Cline\JWT\Encoding\ChainedFormatter;
use Cline\JWT\Encoding\JoseEncoder;
use Cline\JWT\Support\DefaultBuilderFactory;
use Closure;
use NoDiscard;

use function is_callable;

/**
 * High-level immutable configuration object for issuing and validating JWTs.
 *
 * A configuration combines the cryptographic material that defines how tokens
 * are signed with the runtime collaborators needed to build, parse, and
 * validate them. It exists as the package's framework-agnostic composition root
 * for consumers who want a single object that can be copied and specialized for
 * a given application context or profile.
 *
 * Runtime collaborators are stored separately in {@see RuntimeConfiguration} so
 * "with*" methods can replace container-aware infrastructure without mutating
 * the signer and key pair that define the cryptographic identity of the
 * configuration.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class Configuration
{
    private RuntimeConfiguration $runtime;

    /** @var array<ConstraintInterface> */
    private array $validationConstraints;

    /**
     * @param null|BuilderFactoryInterface|callable(ClaimsFormatterInterface): BuilderInterface $builderFactory
     */
    private function __construct(
        private SignerInterface $signer,
        private KeyInterface $signingKey,
        private KeyInterface $verificationKey,
        private EncoderInterface $encoder,
        private DecoderInterface $decoder,
        ?ParserInterface $parser,
        ?ValidatorInterface $validator,
        BuilderFactoryInterface|callable|null $builderFactory,
        ?NowProviderInterface $nowProvider,
        ConstraintInterface ...$validationConstraints,
    ) {
        // Start from environment-aware defaults, then layer explicit overrides.
        $runtime = RuntimeConfiguration::defaults($encoder, $decoder);

        if ($parser instanceof ParserInterface) {
            $runtime = $runtime->withParser($parser);
        }

        if ($validator instanceof ValidatorInterface) {
            $runtime = $runtime->withValidator($validator);
        }

        if ($builderFactory instanceof BuilderFactoryInterface || is_callable($builderFactory)) {
            $runtime = $runtime->withBuilderFactory(
                $this->normalizeBuilderFactory($builderFactory, $encoder),
            );
        }

        if ($nowProvider instanceof NowProviderInterface) {
            $runtime = $runtime->withNowProvider($nowProvider);
        }

        $this->runtime = $runtime;
        $this->validationConstraints = $validationConstraints;
    }

    /**
     * Create a configuration for asymmetric algorithms with distinct signing and
     * verification keys.
     *
     * This is the typical entry point for RSA and ECDSA signers where the public
     * verification key is intentionally different from the private signing key.
     */
    #[NoDiscard()]
    public static function forAsymmetricSigner(
        SignerInterface $signer,
        KeyInterface $signingKey,
        KeyInterface $verificationKey,
        EncoderInterface $encoder = new JoseEncoder(),
        DecoderInterface $decoder = new JoseEncoder(),
    ): self {
        return new self(
            $signer,
            $signingKey,
            $verificationKey,
            $encoder,
            $decoder,
            null,
            null,
            null,
            null,
        );
    }

    /**
     * Create a configuration for symmetric algorithms that reuse a single key
     * for both signing and verification.
     */
    #[NoDiscard()]
    public static function forSymmetricSigner(
        SignerInterface $signer,
        KeyInterface $key,
        EncoderInterface $encoder = new JoseEncoder(),
        DecoderInterface $decoder = new JoseEncoder(),
    ): self {
        return new self(
            $signer,
            $key,
            $key,
            $encoder,
            $decoder,
            null,
            null,
            null,
            null,
        );
    }

    /**
     * @param BuilderFactoryInterface|callable(ClaimsFormatterInterface): BuilderInterface $builderFactory
     *
     * Return a cloned configuration with a different builder factory strategy.
     *
     * Callers may supply a full factory or a closure that receives the claims
     * formatter selected for the current issuance flow.
     */
    #[NoDiscard()]
    public function withBuilderFactory(BuilderFactoryInterface|callable $builderFactory): self
    {
        return new self(
            $this->signer,
            $this->signingKey,
            $this->verificationKey,
            $this->encoder,
            $this->decoder,
            $this->runtime->parser(),
            $this->runtime->validator(),
            $builderFactory,
            $this->runtime->nowProvider(),
            ...$this->validationConstraints,
        );
    }

    /**
     * Create a token builder using the configured factory and claim formatter.
     *
     * When no formatter is provided, the package's default chained formatter is
     * used so audience normalization and date conversion behavior stay aligned
     * with the rest of the JWT stack.
     */
    public function builder(?ClaimsFormatterInterface $claimFormatter = null): BuilderInterface
    {
        return $this->runtime->builderFactory()->create($claimFormatter ?? ChainedFormatter::default());
    }

    /**
     * Get the parser that should be used to decode compact JWT strings.
     */
    public function parser(): ParserInterface
    {
        return $this->runtime->parser();
    }

    /**
     * Return a cloned configuration with a replacement parser.
     */
    #[NoDiscard()]
    public function withParser(ParserInterface $parser): self
    {
        return new self(
            $this->signer,
            $this->signingKey,
            $this->verificationKey,
            $this->encoder,
            $this->decoder,
            $parser,
            $this->runtime->validator(),
            $this->runtime->builderFactory(),
            $this->runtime->nowProvider(),
            ...$this->validationConstraints,
        );
    }

    /**
     * Get the signer that defines the algorithm used for issued tokens.
     */
    public function signer(): SignerInterface
    {
        return $this->signer;
    }

    /**
     * Get the private or shared key used when issuing new tokens.
     */
    public function signingKey(): KeyInterface
    {
        return $this->signingKey;
    }

    /**
     * Get the key used when verifying incoming token signatures.
     */
    public function verificationKey(): KeyInterface
    {
        return $this->verificationKey;
    }

    /**
     * Get the validator responsible for enforcing configured constraints.
     */
    public function validator(): ValidatorInterface
    {
        return $this->runtime->validator();
    }

    /**
     * Get the current clock source used for time-based validation.
     */
    public function nowProvider(): NowProviderInterface
    {
        return $this->runtime->nowProvider();
    }

    /**
     * Return a cloned configuration with a different validator.
     */
    #[NoDiscard()]
    public function withValidator(ValidatorInterface $validator): self
    {
        return new self(
            $this->signer,
            $this->signingKey,
            $this->verificationKey,
            $this->encoder,
            $this->decoder,
            $this->runtime->parser(),
            $validator,
            $this->runtime->builderFactory(),
            $this->runtime->nowProvider(),
            ...$this->validationConstraints,
        );
    }

    /**
     * Get the default validation constraints that should be applied whenever the
     * configuration is used to validate a token.
     *
     * @return array<ConstraintInterface>
     */
    public function validationConstraints(): array
    {
        return $this->validationConstraints;
    }

    /**
     * Return a cloned configuration with a different clock abstraction.
     */
    #[NoDiscard()]
    public function withNowProvider(NowProviderInterface $nowProvider): self
    {
        return new self(
            $this->signer,
            $this->signingKey,
            $this->verificationKey,
            $this->encoder,
            $this->decoder,
            $this->runtime->parser(),
            $this->runtime->validator(),
            $this->runtime->builderFactory(),
            $nowProvider,
            ...$this->validationConstraints,
        );
    }

    /**
     * Replace the configuration's default validation constraint set.
     *
     * The provided constraints become the canonical baseline for future
     * validation operations; they do not merge with the previous list.
     */
    #[NoDiscard()]
    public function withValidationConstraints(ConstraintInterface ...$validationConstraints): self
    {
        return new self(
            $this->signer,
            $this->signingKey,
            $this->verificationKey,
            $this->encoder,
            $this->decoder,
            $this->runtime->parser(),
            $this->runtime->validator(),
            $this->runtime->builderFactory(),
            $this->runtime->nowProvider(),
            ...$validationConstraints,
        );
    }

    /**
     * Normalize the supported builder factory inputs into the package contract.
     *
     * Closures are wrapped in an adapter so callers can provide lightweight custom
     * factories without implementing BuilderFactoryInterface directly.
     */
    private function normalizeBuilderFactory(
        BuilderFactoryInterface|callable|null $builderFactory,
        EncoderInterface $encoder,
    ): BuilderFactoryInterface {
        if ($builderFactory instanceof BuilderFactoryInterface) {
            return $builderFactory;
        }

        if (is_callable($builderFactory)) {
            /** @var Closure(ClaimsFormatterInterface): BuilderInterface $builderFactory */
            $builderFactory = Closure::fromCallable($builderFactory);

            return new readonly class($builderFactory) implements BuilderFactoryInterface
            {
                public function __construct(
                    /** @var Closure(ClaimsFormatterInterface): BuilderInterface */
                    private Closure $builderFactory,
                ) {}

                /**
                 * Adapt the user-provided closure to the package factory
                 * contract without losing formatter customization.
                 */
                public function create(ClaimsFormatterInterface $claimsFormatter): BuilderInterface
                {
                    return ($this->builderFactory)($claimsFormatter);
                }
            };
        }

        return new DefaultBuilderFactory($encoder);
    }
}
