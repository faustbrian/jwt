<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\JWT;

use Cline\JWT\Contracts\BuilderFactoryInterface;
use Cline\JWT\Contracts\JwtProfileRepositoryInterface;
use Cline\JWT\Contracts\NowProviderInterface;
use Cline\JWT\Contracts\ParserInterface;
use Cline\JWT\Contracts\Signer\KeyInterface;
use Cline\JWT\Contracts\SignerInterface;
use Cline\JWT\Contracts\UnencryptedTokenInterface;
use Cline\JWT\Contracts\Validation\ConstraintInterface;
use Cline\JWT\Contracts\Validation\SignedWithInterface;
use Cline\JWT\Contracts\Validation\ValidAtInterface;
use Cline\JWT\Contracts\ValidatorInterface;
use Cline\JWT\Encoding\ChainedFormatter;
use Cline\JWT\Exceptions\JwtProfileRepositoryNotConfigured;
use Cline\JWT\Exceptions\ParserMustReturnUnencryptedToken;
use Illuminate\Container\Container;
use NoDiscard;

use function throw_unless;

/**
 * High-level entry point for issuing, parsing, and profile-driven JWT operations.
 *
 * The facade wraps the lower-level parser, builder factory, validator, and clock so
 * applications can work with a single cohesive surface. It also optionally resolves
 * named profiles from the container, which lets Laravel consumers centralize signer
 * and claim policy in configuration instead of wiring everything manually.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class JwtFacade
{
    private RuntimeConfiguration $runtime;

    private ?JwtProfileRepositoryInterface $profiles;

    /**
     * Create a facade from either a full runtime configuration or individual parts.
     *
     * Passing RuntimeConfiguration is the authoritative path; otherwise a fresh
     * default runtime is created and selectively overridden with the supplied
     * collaborators. Profile resolution is lazy against the container when no
     * repository is provided explicitly.
     */
    public function __construct(
        ParserInterface|RuntimeConfiguration|null $parser = null,
        ?BuilderFactoryInterface $builderFactory = null,
        ?ValidatorInterface $validator = null,
        ?NowProviderInterface $nowProvider = null,
        ?JwtProfileRepositoryInterface $profiles = null,
    ) {
        if ($parser instanceof RuntimeConfiguration) {
            $this->runtime = $parser;
            $this->profiles = $profiles ?? $this->resolveProfiles();

            return;
        }

        $runtime = RuntimeConfiguration::defaults();

        if ($parser instanceof ParserInterface) {
            $runtime = $runtime->withParser($parser);
        }

        if ($builderFactory instanceof BuilderFactoryInterface) {
            $runtime = $runtime->withBuilderFactory($builderFactory);
        }

        if ($validator instanceof ValidatorInterface) {
            $runtime = $runtime->withValidator($validator);
        }

        if ($nowProvider instanceof NowProviderInterface) {
            $runtime = $runtime->withNowProvider($nowProvider);
        }

        $this->runtime = $runtime;
        $this->profiles = $profiles ?? $this->resolveProfiles();
    }

    /**
     * Issue a new signed token using the provided signer, key, and request blueprint.
     *
     * Claims are formatted with Unix timestamp semantics before signing so generated
     * tokens remain interoperable with typical JWT consumers.
     */
    #[NoDiscard()]
    public function issue(
        SignerInterface $signer,
        KeyInterface $signingKey,
        IssueTokenRequest $request = new IssueTokenRequest(),
    ): UnencryptedTokenInterface {
        $builder = $this->runtime->builderFactory()->create(ChainedFormatter::withUnixTimestampDates());
        $now = $this->runtime->nowProvider()->now();

        return $request->applyTo($builder, $now)->getToken($signer, $signingKey);
    }

    /**
     * Resolve a named JWT profile from the configured repository.
     *
     * When no name is provided, the repository decides which profile is the default.
     *
     * @throws JwtProfileRepositoryNotConfigured When no profile repository has been configured
     */
    #[NoDiscard()]
    public function profile(?string $name = null): JwtProfile
    {
        $profiles = $this->profiles ?? $this->resolveProfiles();

        throw_unless($profiles instanceof JwtProfileRepositoryInterface, JwtProfileRepositoryNotConfigured::missingBinding());

        return $profiles->get($name);
    }

    /**
     * Issue a token using a named profile plus per-request overrides.
     *
     * The caller-supplied request is merged on top of profile defaults so explicit
     * token-specific values win without discarding configured baseline claims.
     */
    #[NoDiscard()]
    public function issueFor(?string $profile = null, IssueTokenRequest $request = new IssueTokenRequest()): UnencryptedTokenInterface
    {
        $resolvedProfile = $this->profile($profile);

        return $this->issue(
            $resolvedProfile->signer(),
            $resolvedProfile->signingKey(),
            $resolvedProfile->issueRequest()->merge($request),
        );
    }

    /**
     * Parse a JWT string and assert it against explicit signature, temporal, and
     * additional validation constraints.
     *
     * @param non-empty-string $jwt
     */
    #[NoDiscard()]
    public function parse(
        string $jwt,
        SignedWithInterface $signedWith,
        ValidAtInterface $validAt,
        ConstraintInterface ...$constraints,
    ): UnencryptedTokenInterface {
        $token = $this->runtime->parser()->parse($jwt);

        throw_unless($token instanceof UnencryptedTokenInterface, ParserMustReturnUnencryptedToken::enforced());

        $this->runtime->validator()->assert(
            $token,
            $signedWith,
            $validAt,
            ...$constraints,
        );

        return $token;
    }

    /**
     * Parse a JWT string using the validation policy implied by a named profile.
     *
     * Profile constraints are applied before any caller-supplied extras so the
     * repository-defined baseline policy always participates in validation.
     *
     * @param non-empty-string $jwt
     */
    #[NoDiscard()]
    public function parseFor(
        string $jwt,
        ?string $profile = null,
        ConstraintInterface ...$constraints,
    ): UnencryptedTokenInterface {
        $resolvedProfile = $this->profile($profile);

        return $this->parse(
            $jwt,
            $resolvedProfile->signatureConstraint(),
            $resolvedProfile->validAtConstraint($this->runtime->nowProvider()),
            ...$resolvedProfile->validationConstraints(),
            ...$constraints,
        );
    }

    /**
     * Resolve the profile repository from the global container when available.
     *
     * This remains nullable so the facade can still be used outside Laravel or in
     * tests that only perform direct issue/parse operations.
     */
    private function resolveProfiles(): ?JwtProfileRepositoryInterface
    {
        $container = Container::getInstance();

        if (!$container->bound(JwtProfileRepositoryInterface::class)) {
            return null;
        }

        return $container->make(JwtProfileRepositoryInterface::class);
    }
}
