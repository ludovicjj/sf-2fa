<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Mercure\Update;
use Symfony\Component\Mercure\HubInterface;

class ChatController extends AbstractController
{
    #[Route('/chat', name:'app_chat')]
    public function send(HubInterface $hub): Response
    {
        $update = new Update(
            'http://monsite.com/books',
            json_encode([
                'message' => 'Bye bye Petra !!!',
                'name' => 'Dominique Baton'
            ])
        );

        $hub->publish($update);

        return new JsonResponse(['message' => 'success']);
    }
}