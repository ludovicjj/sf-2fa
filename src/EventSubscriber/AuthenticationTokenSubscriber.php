<?php

namespace App\EventSubscriber;

use App\Entity\User;
use App\Security\Context\AuthenticationContextFactoryInterface;
use App\Security\Token\YoloProviderInitiator;
use App\Security\Token\YoloTokenInterface;
use RuntimeException;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Http\Event\AuthenticationTokenCreatedEvent;
use Symfony\Component\Security\Core\Event\AuthenticationEvent;
use Symfony\Component\Security\Core\AuthenticationEvents;

class AuthenticationTokenSubscriber implements EventSubscriberInterface
{
    public const LISTENER_PRIORITY = PHP_INT_MAX - 1;

    public const RESPONSE_LISTENER_PRIORITY = 1;

    public function __construct(
        private readonly RequestStack $requestStack,
        private readonly AuthenticationContextFactoryInterface $authenticationContextFactory,
        private readonly YoloProviderInitiator $yoloProviderInitiator,
        private readonly TokenStorageInterface $tokenStorage,
        private readonly UrlGeneratorInterface $urlGenerator
    ) {
    }

    public function onAuthenticationTokenCreated(AuthenticationTokenCreatedEvent $event): void
    {
        $token = $event->getAuthenticatedToken();

        if ($token instanceof YoloTokenInterface) {
            return;
        }

        $request = $this->getRequest();
        $passport = $event->getPassport();
        $user = $passport->getUser();

        if (!$user instanceof User) {
            return;
        }

        if (!$user->isEmailAuthEnabled()) {
            return;
        }


        $context = $this->authenticationContextFactory->create($request, $token, $passport, 'main');
        $newToken = $this->yoloProviderInitiator->beginTwoFactorAuthentication($context);

        if (null === $newToken) {
            return;
        }

        $event->setAuthenticatedToken($newToken);
    }

    public function onKernelResponse(ResponseEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }
        $currentToken = $this->tokenStorage->getToken();

        if ($currentToken instanceof YoloTokenInterface) {
            $request = $event->getRequest();
            $url = $this->urlGenerator->generate('app_f2a_email');
            if ($request->getRequestUri() !== $url) {
                $event->setResponse(
                    new RedirectResponse($url)
                );
            }
        }
    }

    public function onLogin(AuthenticationEvent $event): void
    {
        $token = $event->getAuthenticationToken();

        // We have a TwoFactorToken, make sure the security.authentication.success is not propagated to other
        // listeners, since we do not have a successful login (yet)
        if (!($token instanceof YoloTokenInterface)) {
            return;
        }

        $event->stopPropagation();
    }

    private function getRequest(): Request
    {
        $request = $this->requestStack->getMainRequest();
        if (null === $request) {
            throw new RuntimeException('No request available');
        }

        return $request;
    }

    public static function getSubscribedEvents(): array
    {
        return [
            AuthenticationTokenCreatedEvent::class => 'onAuthenticationTokenCreated',
            AuthenticationEvents::AUTHENTICATION_SUCCESS => ['onLogin', self::LISTENER_PRIORITY],
            KernelEvents::RESPONSE => ['onKernelResponse', self::RESPONSE_LISTENER_PRIORITY],
        ];
    }
}