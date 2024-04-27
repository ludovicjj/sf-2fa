<?php

namespace App\Security\Token;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserInterface;

interface YoloTokenInterface extends TokenInterface
{
    /**
     * @internal
     */
    public const ATTRIBUTE_NAME_USE_REMEMBER_ME = 'use_remember_me';

    /**
     * Return the authenticated token.
     */
    public function getAuthenticatedToken(): TokenInterface;

    /**
     * Returns a user representation.
     *
     * For a TwoFactorToken this is not nullable.
     */
    public function getUser(): UserInterface;

    /**
     * Duplicate the token with credentials.
     */
    public function createWithCredentials(string $credentials): self;

    /**
     * Return the firewall name.
     */
    public function getFirewallName(): string;

    /**
     * Return list of two-factor providers (their aliases), which are available.
     *
     * @return string[]
     */
    public function getProviders(): array;

    /**
     * Change the current two-factor provider. Provider alias is passed as an argument.
     */
    public function preferProvider(string $preferredProvider): void;

    /**
     * Return the alias of the two-factor provider, which is currently active.
     */
    public function getCurrentProvider(): ?string;

    /**
     * Flag a two-factor provider as complete. The provider's alias is passed as the argument.
     */
    public function setProviderComplete(string $providerName): void;

    /**
     * Check if all two-factor providers have been completed.
     */
    public function allProvidersAuthenticated(): bool;

    /**
     * Check if a two-factor provider has completed preparation. The provider's alias is passed as the argument.
     */
    public function isProviderPrepared(string $providerName): bool;

    /**
     * Remember when a two-factor provider has completed preparation. The provider's alias is passed as the argument.
     */
    public function setProviderPrepared(string $providerName): void;
}