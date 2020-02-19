<?php

namespace Esc\JwtAuth\Security;

use Esc\User\Entity\EscUser;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class UserChecker implements UserCheckerInterface
{
    public function checkPreAuth(UserInterface $user)
    {
        if (!$user instanceof EscUser) {
            return;
        }

        // user is deleted, show a generic Account Not Found message.
        if (!$user->getActive()) {
            // or to customize the message shown
            throw new CustomUserMessageAuthenticationException(
                'Utente non attivo. Contattare l\'amministratore di sistema'
            );
        }
    }

    public function checkPostAuth(UserInterface $user)
    {
        if (!$user instanceof EscUser) {
            return;
        }
    }
}
