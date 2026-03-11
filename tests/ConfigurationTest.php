<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests;

use Cline\JWT\Configuration;
use Cline\JWT\Contracts\BuilderInterface;
use Cline\JWT\Contracts\ClaimsFormatterInterface;
use Cline\JWT\Contracts\DecoderInterface;
use Cline\JWT\Contracts\EncoderInterface;
use Cline\JWT\Contracts\ParserInterface;
use Cline\JWT\Contracts\SignerInterface;
use Cline\JWT\Contracts\Validation\ConstraintInterface;
use Cline\JWT\Contracts\ValidatorInterface;
use Cline\JWT\Encoding\ChainedFormatter;
use Cline\JWT\Encoding\JoseEncoder;
use Cline\JWT\Signer\Key\InMemory;
use Cline\JWT\Token\Builder as BuilderImpl;
use Cline\JWT\Token\Parser as ParserImpl;
use Cline\JWT\Validation\Validator;
use PHPUnit\Framework\Attributes\Before;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;

/**
 * @author Brian Faust <brian@cline.sh>
 * @internal
 */
#[CoversClass(Configuration::class)]
#[UsesClass(ChainedFormatter::class)]
#[UsesClass(InMemory::class)]
#[UsesClass(BuilderImpl::class)]
#[UsesClass(ParserImpl::class)]
#[UsesClass(Validator::class)]
final class ConfigurationTest extends TestCase
{
    private ParserInterface&Stub $parser;

    private SignerInterface&Stub $signer;

    private EncoderInterface&Stub $encoder;

    private DecoderInterface&Stub $decoder;

    private ValidatorInterface&Stub $validator;

    private ConstraintInterface&Stub $validationConstraints;

    #[Before()]
    public function createDependencies(): void
    {
        $this->signer = $this->createStub(SignerInterface::class);
        $this->encoder = $this->createStub(EncoderInterface::class);
        $this->decoder = $this->createStub(DecoderInterface::class);
        $this->parser = $this->createStub(ParserInterface::class);
        $this->validator = $this->createStub(ValidatorInterface::class);
        $this->validationConstraints = $this->createStub(ConstraintInterface::class);
    }

    #[Test()]
    public function for_asymmetric_signer_should_configure_signer_and_both_keys(): void
    {
        $signingKey = InMemory::plainText('private');
        $verificationKey = InMemory::plainText('public');

        $config = Configuration::forAsymmetricSigner($this->signer, $signingKey, $verificationKey);

        $this->assertSame($this->signer, $config->signer());
        $this->assertSame($signingKey, $config->signingKey());
        $this->assertSame($verificationKey, $config->verificationKey());
    }

    #[Test()]
    public function for_symmetric_signer_should_configure_signer_and_both_keys(): void
    {
        $key = InMemory::plainText('private');
        $config = Configuration::forSymmetricSigner($this->signer, $key);

        $this->assertSame($this->signer, $config->signer());
        $this->assertSame($key, $config->signingKey());
        $this->assertSame($key, $config->verificationKey());
    }

    #[Test()]
    public function builder_should_create_a_builder_with_default_encoder_and_claim_factory(): void
    {
        $config = Configuration::forSymmetricSigner(
            new KeyDumpSigner(),
            InMemory::plainText('private'),
        );
        $builder = $config->builder();

        $this->assertInstanceOf(BuilderImpl::class, $builder);
        $this->assertNotEquals(BuilderImpl::new($this->encoder, ChainedFormatter::default()), $builder);
        $this->assertEquals(BuilderImpl::new(
            new JoseEncoder(),
            ChainedFormatter::default(),
        ), $builder);
    }

    #[Test()]
    public function builder_should_create_a_builder_with_customized_encoder_and_claim_factory(): void
    {
        $config = Configuration::forSymmetricSigner(
            new KeyDumpSigner(),
            InMemory::plainText('private'),
            $this->encoder,
        );
        $builder = $config->builder();

        $this->assertInstanceOf(BuilderImpl::class, $builder);
        $this->assertEquals(BuilderImpl::new($this->encoder, ChainedFormatter::default()), $builder);
    }

    #[Test()]
    public function builder_should_use_builder_factory_when_that_is_configured(): void
    {
        $builder = $this->createStub(BuilderInterface::class);

        $config = Configuration::forSymmetricSigner(
            new KeyDumpSigner(),
            InMemory::plainText('private'),
        );
        $newConfig = $config->withBuilderFactory(
            static fn (): BuilderInterface => $builder,
        );
        $this->assertNotSame($builder, $config->builder());
        $this->assertSame($builder, $newConfig->builder());
    }

    #[Test()]
    public function parser_should_return_a_parser_with_default_decoder(): void
    {
        $config = Configuration::forSymmetricSigner(
            new KeyDumpSigner(),
            InMemory::plainText('private'),
        );
        $parser = $config->parser();

        $this->assertNotEquals(
            new ParserImpl($this->decoder),
            $parser,
        );
    }

    #[Test()]
    public function parser_should_return_a_parser_with_customized_decoder(): void
    {
        $config = Configuration::forSymmetricSigner(
            new KeyDumpSigner(),
            InMemory::plainText('private'),
            decoder: $this->decoder,
        );
        $parser = $config->parser();

        $this->assertEquals(
            new ParserImpl($this->decoder),
            $parser,
        );
    }

    #[Test()]
    public function parser_should_not_create_an_instance_if_it_was_configured(): void
    {
        $config = Configuration::forSymmetricSigner(
            new KeyDumpSigner(),
            InMemory::plainText('private'),
        );
        $newConfig = $config->withParser($this->parser);

        $this->assertNotSame($this->parser, $config->parser());
        $this->assertSame($this->parser, $newConfig->parser());
    }

    #[Test()]
    public function validator_should_return_the_default_when_it_was_not_configured(): void
    {
        $config = Configuration::forSymmetricSigner(
            new KeyDumpSigner(),
            InMemory::plainText('private'),
        );
        $validator = $config->validator();

        $this->assertNotSame($this->validator, $validator);
    }

    #[Test()]
    public function validator_should_return_the_configured_validator(): void
    {
        $config = Configuration::forSymmetricSigner(
            new KeyDumpSigner(),
            InMemory::plainText('private'),
        );
        $newConfig = $config->withValidator($this->validator);

        $this->assertNotSame($this->validator, $config->validator());
        $this->assertSame($this->validator, $newConfig->validator());
    }

    #[Test()]
    public function validation_constraints_should_return_an_empty_array_when_it_was_not_configured(): void
    {
        $config = Configuration::forSymmetricSigner(
            new KeyDumpSigner(),
            InMemory::plainText('private'),
        );

        $this->assertSame([], $config->validationConstraints());
    }

    #[Test()]
    public function validation_constraints_should_return_the_configured_validator(): void
    {
        $config = Configuration::forSymmetricSigner(
            new KeyDumpSigner(),
            InMemory::plainText('private'),
        );
        $newConfig = $config->withValidationConstraints($this->validationConstraints);

        $this->assertNotSame([$this->validationConstraints], $config->validationConstraints());
        $this->assertSame([$this->validationConstraints], $newConfig->validationConstraints());
    }

    #[Test()]
    public function custom_claim_formatter_can_be_used(): void
    {
        $formatter = $this->createStub(ClaimsFormatterInterface::class);
        $config = Configuration::forSymmetricSigner(
            new KeyDumpSigner(),
            InMemory::plainText('private'),
        );

        $this->assertEquals(BuilderImpl::new(
            new JoseEncoder(),
            $formatter,
        ), $config->builder($formatter));
    }
}
