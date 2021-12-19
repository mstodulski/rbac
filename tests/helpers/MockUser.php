<?php
namespace test\helpers;

use mstodulski\rbac\interfaces\UserInterface;

class MockUser implements UserInterface
{
    private ?string $login;
    private ?string $password;
    private bool $internalUser = false;
    private bool $twoFactorAuthentication = false;

    public function getLogin() : ?string
    {
        return $this->login;
    }

    public function setLogin(string $login) : void
    {
        $this->login = $login;
    }

    public function getPassword() : ?string
    {
        return $this->password;
    }

    public function setPassword(string $password) : void
    {
        $this->password = $password;
    }

    public function isInternalUser() : bool
    {
        return $this->internalUser;
    }

    public function isTwoFactorAuthentication() : bool
    {
        return $this->twoFactorAuthentication;
    }

    public function setTwoFactorAuthentication(bool $twoFactorAuthentication): void
    {
        $this->twoFactorAuthentication = $twoFactorAuthentication;
    }
}