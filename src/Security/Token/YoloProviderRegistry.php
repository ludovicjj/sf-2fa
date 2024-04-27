<?php

namespace App\Security\Token;

class YoloProviderRegistry
{

    public function __construct(private iterable $providers)
    {
    }


    public function getAllProviders(): iterable
    {
        return $this->providers;
    }

    public function getProvider(string $providerName)
    {
        foreach ($this->providers as $name => $provider) {
            if ($name === $providerName) {
                return $provider;
            }
        }

        throw new \Exception(sprintf('Two-factor provider "%s" does not exist.', $providerName));
    }
}