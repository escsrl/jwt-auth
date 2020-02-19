<?php

namespace Esc\JwtAuth\Security;

use Esc\User\Entity\EscUser;
use Lexik\Bundle\JWTAuthenticationBundle\Event\JWTCreatedEvent;

class JWTCreatedListener
{
    public function onJwtCreated(JWTCreatedEvent $event): void
    {
        /** @var EscUser $user */
        $user = $event->getUser();

        $payload = $event->getData();
        $payload['id'] = $user->getId();

        $event->setData($payload);
    }
}
