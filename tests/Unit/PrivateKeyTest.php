<?php

declare(strict_types=1);

use Spickyyy1\NhsLogin\Exceptions\NhsLoginConfigurationException;
use Spickyyy1\NhsLogin\Support\PrivateKey;
use Spickyyy1\NhsLogin\Tests\RsaKeyPair;

/**
 * The errors every new integrator meets first. Their messages are most of the
 * package's support surface, so they are worth pinning down.
 */
it('reads the key from inline PEM contents', function () {
    $pem = RsaKeyPair::shared()->privateKey();

    expect(PrivateKey::resolve($pem, null))->toBe($pem);
});

it('accepts the escaped newlines an environment variable forces on you', function () {
    // Env vars cannot hold real newlines, so platforms hand over \n literally.
    $pem = RsaKeyPair::shared()->privateKey();
    $escaped = str_replace("\n", '\n', $pem);

    expect(PrivateKey::resolve($escaped, null))->toBe($pem);
});

it('reads the key from a file when no contents are given', function () {
    $path = tempnam(sys_get_temp_dir(), 'nhs-key-');
    file_put_contents($path, $pem = RsaKeyPair::shared()->privateKey());

    try {
        expect(PrivateKey::resolve(null, $path))->toBe($pem);
    } finally {
        unlink($path);
    }
});

it('prefers inline contents over a path', function () {
    $pem = RsaKeyPair::shared()->privateKey();

    expect(PrivateKey::resolve($pem, '/definitely/not/here.pem'))->toBe($pem);
});

it('says so when no key is configured at all', function () {
    expect(fn () => PrivateKey::resolve(null, null))
        ->toThrow(NhsLoginConfigurationException::class, 'NHS_LOGIN_PRIVATE_KEY');

    expect(fn () => PrivateKey::resolve('   ', '  '))
        ->toThrow(NhsLoginConfigurationException::class);
});

it('names the path it could not read', function () {
    expect(fn () => PrivateKey::resolve(null, '/definitely/not/here.pem'))
        ->toThrow(NhsLoginConfigurationException::class, '/definitely/not/here.pem');
});

it('derives the public half of a key', function () {
    $public = PrivateKey::publicKey(RsaKeyPair::shared()->privateKey());

    expect($public)->toContain('BEGIN PUBLIC KEY');
});

it('refuses to derive a public half from something that is not a key', function () {
    expect(fn () => PrivateKey::publicKey('-----BEGIN PRIVATE KEY-----nonsense'))
        ->toThrow(NhsLoginConfigurationException::class, 'RSA key in PEM format');
});

it('handles a passphrase-protected key', function () {
    $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    openssl_pkey_export($key, $pem, 'correct-horse');

    expect(PrivateKey::publicKey($pem, 'correct-horse'))->toContain('BEGIN PUBLIC KEY')
        ->and(fn () => PrivateKey::publicKey($pem, 'wrong'))
        ->toThrow(NhsLoginConfigurationException::class);
});
