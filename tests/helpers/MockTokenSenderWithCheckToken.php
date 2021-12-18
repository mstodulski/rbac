<?php
namespace test\helpers;

use mstodulski\rbac\interfaces\TokenSenderInterface;
use mstodulski\rbac\interfaces\UserInterface;

class MockTokenSenderWithCheckToken implements TokenSenderInterface
{
    public function sendToken(UserInterface $user, $content)
    {

    }

    public function getCommunicationEndpoint(UserInterface $user) : ?string
    {
        return 'test endpoint';
    }

    public function checkToken(UserInterface $user, string $token) : bool
    {
        return true;
    }
}
