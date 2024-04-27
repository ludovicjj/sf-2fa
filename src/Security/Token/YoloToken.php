<?php

namespace App\Security\Token;

use InvalidArgumentException;
use LogicException;
use RuntimeException;
use Scheb\TwoFactorBundle\Security\UsernameHelper;
use Stringable;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class YoloToken implements YoloTokenInterface, Stringable
{
    private array $providers;
    private array $preparedProviders = [];

    private array $attributes = [];

    private TokenInterface $authenticatedToken;

    public function __construct(
        TokenInterface $authenticatedToken,
        private ?string $credentials,
        private string $firewallName,
        array $providers,
    ) {
        $this->authenticatedToken = $authenticatedToken;
        $this->providers = $providers;
    }

    public function getUser(): UserInterface
    {
        $user = $this->authenticatedToken->getUser();
        if (null === $user) {
            throw new RuntimeException('The authenticated token must have a user object set, though null was returned.');
        }

        return $user;
    }

    public function setUser(UserInterface $user)
    {
        $this->authenticatedToken->setUser($user);
    }

    public function getUserIdentifier(): string
    {
        return UsernameHelper::getTokenUsername($this->authenticatedToken);
    }

    public function getUsername(): string
    {
        return $this->getUserIdentifier();
    }

    public function getRoles(): array
    {
        return [];
    }

    public function getRoleNames(): array
    {
        return [];
    }

    public function createWithCredentials(string $credentials): YoloTokenInterface
    {
        $credentialsToken = new self($this->authenticatedToken, $credentials, $this->firewallName, $this->providers);
        foreach (array_keys($this->preparedProviders) as $preparedProviderName) {
            $credentialsToken->setProviderPrepared($preparedProviderName);
        }

        $credentialsToken->setAttributes($this->getAttributes());

        return $credentialsToken;
    }

    public function getCredentials(): ?string
    {
        return $this->credentials;
    }

    public function eraseCredentials(): void
    {
        $this->credentials = null;
    }

    public function getAuthenticatedToken(): TokenInterface
    {
        return $this->authenticatedToken;
    }

    public function getProviders(): array
    {
        return $this->providers;
    }

    public function preferProvider(string $preferredProvider): void
    {
        $this->removeProvider($preferredProvider);
        array_unshift($this->providers, $preferredProvider);
    }

    public function getCurrentProvider(): ?string
    {
        $first = reset($this->providers);

        return false !== $first ? $first : null;
    }

    public function isProviderPrepared(string $providerName): bool
    {
        return $this->preparedProviders[$providerName] ?? false;
    }

    public function setProviderPrepared(string $providerName): void
    {
        $this->preparedProviders[$providerName] = true;
    }

    public function setProviderComplete(string $providerName): void
    {
        if (!$this->isProviderPrepared($providerName)) {
            throw new LogicException(sprintf('Two-factor provider "%s" cannot be completed because it was not prepared.', $providerName));
        }

        $this->removeProvider($providerName);
    }

    private function removeProvider(string $providerName): void
    {
        $key = array_search($providerName, $this->providers, true);
        if (false === $key) {
            throw new \Exception(sprintf('Two-factor provider "%s" is not active.', $providerName));
        }

        unset($this->providers[$key]);
    }

    public function allProvidersAuthenticated(): bool
    {
        return 0 === count($this->providers);
    }

    public function getFirewallName(): string
    {
        return $this->firewallName;
    }

    public function isAuthenticated(): bool
    {
        return true;
    }

    public function setAuthenticated(bool $isAuthenticated): void
    {
        throw new RuntimeException('Cannot change authenticated once initialized.');
    }

    public function serialize(): string
    {
        return serialize($this->__serialize());
    }

    public function __serialize(): array
    {
        return [
            $this->authenticatedToken,
            $this->credentials,
            $this->firewallName,
            $this->attributes,
            $this->providers,
            $this->preparedProviders,
        ];
    }

    public function unserialize(string $serialized): void
    {
        $this->__unserialize(unserialize($serialized));
    }

    public function __unserialize(array $data): void
    {
        [
            $this->authenticatedToken,
            $this->credentials,
            $this->firewallName,
            $this->attributes,
            $this->providers,
            $this->preparedProviders,
        ] = $data;
    }

    public function getAttributes(): array
    {
        return $this->attributes;
    }

    public function setAttributes(array $attributes): void
    {
        $this->attributes = $attributes;
    }

    public function hasAttribute(string $name): bool
    {
        return array_key_exists($name, $this->attributes);
    }

    public function getAttribute(string $name): mixed
    {
        if (!array_key_exists($name, $this->attributes)) {
            throw new InvalidArgumentException(sprintf('This token has no "%s" attribute.', $name));
        }

        return $this->attributes[$name];
    }

    public function setAttribute(string $name, mixed $value): void
    {
        $this->attributes[$name] = $value;
    }

    public function __toString(): string
    {
        return $this->getUserIdentifier();
    }

}