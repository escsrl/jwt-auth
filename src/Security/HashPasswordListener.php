<?php

namespace Esc\JwtAuth\Security;

use Doctrine\Common\EventSubscriber;
use Doctrine\ORM\Event\LifecycleEventArgs;
use Esc\User\Entity\EscUser;
use Symfony\Component\Security\Core\Encoder\EscUserPasswordEncoderInterface;

final class HashPasswordListener implements EventSubscriber
{
    /** @var EscUserPasswordEncoderInterface */
    private $passwordEncoder;

    /**
     * HashPasswordListener constructor.
     * @param EscUserPasswordEncoderInterface $passwordEncoder
     */
    public function __construct(EscUserPasswordEncoderInterface $passwordEncoder)
    {
        $this->passwordEncoder = $passwordEncoder;
    }

    /**
     * @param LifecycleEventArgs $args
     * @return void
     */
    public function prePersist(LifecycleEventArgs $args): void
    {
        $entity = $args->getEntity();
        if (!$entity instanceof EscUser) {
            return;
        }

        $this->encodePassword($entity);
    }

    /**
     * @param LifecycleEventArgs $args
     * @return void
     */
    public function preUpdate(LifecycleEventArgs $args): void
    {
        $entity = $args->getEntity();
        if (!$entity instanceof EscUser) {
            return;
        }

        $this->encodePassword($entity);
        // necessary to force the update to see the change
        $entityManager = $args->getEntityManager();
        $meta = $entityManager->getClassMetadata(\get_class($entity));
        $entityManager->getUnitOfWork()->recomputeSingleEntityChangeSet($meta, $entity);
    }

    /**
     * {@inheritdoc}
     */
    public function getSubscribedEvents()
    {
        return ['prePersist', 'preUpdate'];
    }

    /**
     * @param EscUser $entity
     * @return void
     */
    private function encodePassword(EscUser $entity): void
    {
        if ($entity->getPlainPassword() === null) {
            return;
        }

        $encoded = $this->passwordEncoder->encodePassword(
            $entity,
            $entity->getPlainPassword()
        );

        $entity->setPassword($encoded);
    }
}
