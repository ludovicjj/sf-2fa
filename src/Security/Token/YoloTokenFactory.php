<?php

namespace App\Security\Token;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

class YoloTokenFactory implements YoloTokenFactoryInterface
{
    public function create(TokenInterface $authenticatedToken, string $firewallName, array $activeProviders): YoloTokenInterface
    {
        return new YoloToken($authenticatedToken, null, $firewallName, $activeProviders);
    }
}