<?php

namespace App\Security\Token;

use App\Security\Context\AuthenticationContext;


class YoloProviderInitiator
{
    public function __construct(
        private readonly YoloTokenFactory $yoloTokenFactory
    ) {
    }

    public function beginTwoFactorAuthentication(AuthenticationContext $context): ?YoloToken
    {
        $activeProviders = $this->getActiveProviders($context);

        $authenticatedToken = $context->getToken();

        if ($activeProviders) {
            return $this->yoloTokenFactory->create($authenticatedToken, $context->getFirewallName(), $activeProviders);
            //$this->setPreferredProvider($yoloToken, $context->getUser()); // Prioritize the user's preferred provider
        }

        return null;
    }

    private function getActiveProviders(AuthenticationContext $context): array
    {
        return [
            'email'
        ];
    }
}