<?php declare(strict_types=1);

return [
    'default' => 'default',

    'profiles' => [
        'default' => [
            'signer' => \Cline\JWT\Signer\Hmac\Sha256::class,
            'signing_key' => [
                'loader' => 'plain',
                'source' => env('JWT_SIGNING_KEY', 'change-me'),
                'passphrase' => env('JWT_SIGNING_KEY_PASSPHRASE', ''),
            ],
            'verification_key' => [
                'loader' => 'plain',
                'source' => env('JWT_VERIFICATION_KEY', env('JWT_SIGNING_KEY', 'change-me')),
                'passphrase' => env('JWT_VERIFICATION_KEY_PASSPHRASE', ''),
            ],
            'ttl' => 'PT5M',
            'leeway' => 'PT0S',
            'issuer' => env('JWT_ISSUER'),
            'audiences' => [],
            'headers' => [],
            'claims' => [],
        ],
    ],
];
