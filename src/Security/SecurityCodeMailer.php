<?php

namespace App\Security;

use Scheb\TwoFactorBundle\Model\Email\TwoFactorInterface;
use Scheb\TwoFactorBundle\Mailer\AuthCodeMailerInterface;
use Symfony\Component\Mailer\Exception\TransportExceptionInterface;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;

class SecurityCodeMailer implements AuthCodeMailerInterface
{
    public function __construct(private readonly MailerInterface $mailer)
    {
    }

    public function sendAuthCode(TwoFactorInterface $user): void
    {
        $authCode = $user->getEmailAuthCode();

        $email = (new Email())
            ->from('no-reply@emple.com')
            ->to($user->getEmailAuthRecipient())
            ->subject('Authentication Code')
            ->html("<p>your authentification code is $authCode</p>");

        try {
            $this->mailer->send($email);
        } catch (TransportExceptionInterface $e) {

        }
    }
}