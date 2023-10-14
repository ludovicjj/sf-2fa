<?php

namespace App\Security;

use App\Entity\User;
use Scheb\TwoFactorBundle\Security\TwoFactor\Provider\Totp\TotpAuthenticatorInterface;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\Exception\AccountExpiredException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAccountStatusException;

class UserChecker implements UserCheckerInterface
{
    public function __construct(
        private readonly RequestStack $requestStack,
        private readonly TotpAuthenticatorInterface $totpAuthenticator
    ) {
    }

    public function checkPreAuth(UserInterface $user): void
    {
        $request = $this->requestStack->getMainRequest();

        if (!$request) {
            return;
        }

        if (!$user instanceof User) {
            return;
        }

        if (!$this->totpAuthenticator->checkCode($user, $request->request->get('_code'))) {
            // allows to customize the error message displayed to the user
            // throw new CustomUserMessageAccountStatusException('Your code is invalide.');
            throw new AccountExpiredException('Invalid code');
        }
    }

    public function checkPostAuth(UserInterface $user): void
    {
        // TODO: Implement checkPostAuth() method.
    }
}