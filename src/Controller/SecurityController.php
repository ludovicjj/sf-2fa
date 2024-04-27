<?php

namespace App\Controller;

use App\Entity\User;
use App\Security\Token\YoloTokenInterface;
use Doctrine\ORM\EntityManagerInterface;
use Scheb\TwoFactorBundle\Security\TwoFactor\Provider\Totp\TotpAuthenticatorInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Http\Attribute\IsGranted;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;
use Endroid\QrCode\Builder\Builder;

class SecurityController extends AbstractController
{
    #[Route('/login', name: 'app_login')]
    public function login(AuthenticationUtils $authenticationUtils): Response
    {
        $error = $authenticationUtils->getLastAuthenticationError();
        $lastUsername = $authenticationUtils->getLastUsername();

        return $this->render('security/index.html.twig', [
            'last_username' => $lastUsername,
            'error'         => $error,
        ]);
    }

    #[Route('/logout', name: 'app_logout', methods: ['GET'])]
    public function logout(): never
    {
        // controller can be blank: it will never be called!
        throw new \Exception('Don\'t forget to activate logout in security.yaml');
    }

    #[Route('/authentication/2fa/enable', name: 'app_2fa_enable')]
    #[IsGranted("IS_AUTHENTICATED_FULLY")]
    public function enable2fa(TotpAuthenticatorInterface $totpAuthenticator, EntityManagerInterface $entityManager)
    {
        /** @var User $user */
        $user = $this->getUser();
        if (!$user->isTotpAuthenticationEnabled()) {
            $user->setTotpSecret($totpAuthenticator->generateSecret());

            $entityManager->flush();
        }

        return $this->render('security/enable2fa.html.twig');
    }

    #[Route('/authentication/2fa/qr-code', name: 'app_qr_code')]
    #[IsGranted("IS_AUTHENTICATED_FULLY")]
    public function displayGoogleAuthenticatorQrCode(TotpAuthenticatorInterface $totpAuthenticator): Response
    {
        /** @var User $user */
        $user = $this->getUser();

        // GET URL for authentication app like google auth
        // user must implement TotpTwoFactorInterface
        $qrCodeContent = $totpAuthenticator->getQRContent($user);

        // Build QR code
        $result = Builder::create()
            ->data($qrCodeContent)
            ->build();

        return new Response($result->getString(), 200, ['Content-Type' => 'image/png']);
    }

    #[Route('/authentication/2fa/email', name: 'app_f2a_email')]
    public function valideEmailCode(Request $request, TokenStorageInterface $tokenStorage): Response
    {
        $code = $request->request->get('_code');
        /** @var User $user */
        $user = $this->getUser();

        if ($request->getMethod() === 'POST') {
            if ($code === $user->getEmailAuthCode()) {
                /** @var YoloTokenInterface $token */
                $token = $tokenStorage->getToken();
                $tokenStorage->setToken($token->getAuthenticatedToken());

                return $this->redirectToRoute('app_home');
            } else {

                return $this->render('security/valid_email_code.html.twig', [
                    'isCsrfProtectionEnabled' => true,
                    'csrfTokenId' => 'hello_word',
                    'errorCodeMessage' => "le code n'est pas valide"
                ]);
            }
        }

        return $this->render('security/valid_email_code.html.twig', [
            'isCsrfProtectionEnabled' => true,
            'csrfTokenId' => 'hello_word'
        ]);
    }
}
