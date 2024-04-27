<?php

namespace App\Security\Context;


use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;

interface AuthenticationContextFactoryInterface
{
    public function create(Request $request, TokenInterface $token, Passport $passport, string $firewallName): \App\Security\Context\AuthenticationContextInterface;
}