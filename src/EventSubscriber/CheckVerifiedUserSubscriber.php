<?php

namespace App\EventSubscriber;

use App\Entity\User;
use App\Security\AccountNotVerifiedAuthenticationException;
use App\Security\LoginFormAuthenticator;
use Scheb\TwoFactorBundle\Security\TwoFactor\Provider\Email\Generator\CodeGeneratorInterface;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Http\Event\CheckPassportEvent;
use Symfony\Component\Security\Http\Event\LoginFailureEvent;

class CheckVerifiedUserSubscriber implements EventSubscriberInterface
{
    public function __construct(
        private readonly CodeGeneratorInterface $codeGenerator,
        private readonly UrlGeneratorInterface $urlGenerator,
        private readonly Security $security,
        private readonly TokenStorageInterface $tokenStorage
    )
    {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            CheckPassportEvent::class => 'onCheckPassport',
            LoginFailureEvent::class => 'onLoginFailure',
        ];
    }

    /**
     * This event is trigger when passport is valid on every firewall
     * @param CheckPassportEvent $event
     * @return void|RedirectResponse
     */
    public function onCheckPassport(CheckPassportEvent $event)
    {
//        $passport = $event->getPassport();
//        $authenticator = $event->getAuthenticator();
//
//        if ($authenticator instanceof LoginFormAuthenticator) {
//            $user = $passport->getUser();
//
//            if ($user instanceof User && $user->isEmailAuthEnabled()) {
//
//                $this->codeGenerator->generateAndSend($user);
//                throw new AccountNotVerifiedAuthenticationException();
//            }
//        }
    }

    public function onLoginFailure(LoginFailureEvent $event)
    {
        if ($event->getException() instanceof AccountNotVerifiedAuthenticationException) {
            $response = new RedirectResponse($this->urlGenerator->generate('app_f2a_email'));
            $event->setResponse($response);
        }
    }
}