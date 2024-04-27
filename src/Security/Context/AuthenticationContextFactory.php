<?php

namespace App\Security\Context;


use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;

class AuthenticationContextFactory implements AuthenticationContextFactoryInterface
{


    public function create(Request $request, TokenInterface $token, Passport $passport, string $firewallName): AuthenticationContextInterface
    {

        $authenticationContext = new AuthenticationContext($request, $token, $passport, $firewallName);
        assert($authenticationContext instanceof AuthenticationContextInterface);

        return $authenticationContext;
    }
}