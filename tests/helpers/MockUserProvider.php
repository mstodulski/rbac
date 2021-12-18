<?php
namespace test\helpers;

use JetBrains\PhpStorm\Pure;
use mstodulski\rbac\interfaces\UserInterface;
use mstodulski\rbac\interfaces\UserProviderInterface;
use mstodulski\rbac\services\PasswordProvider;

class MockUserProvider implements UserProviderInterface
{
    protected PasswordProvider $passwordProvider;
    protected string $salt = 'testtesttesttest';
    const testValidUserName = 'test';
    const testValidUserPassword = 'test';
    const testValidUserWith2FA = 'test2FA';
    const testValidUserPasswordWith2FA = 'test2FA';

    #[Pure] public function __construct()
    {
        $this->passwordProvider = new PasswordProvider();
    }

    public function getUser(string $login) : ?UserInterface
    {
        $user = null;
        if ($login === self::testValidUserName) {
            $user = new MockUser();
            $user->setLogin(self::testValidUserName);
            $user->setPassword($this->passwordProvider->encodePassword($user, self::testValidUserPassword, $this->salt));
            $user->setSalt($this->salt);
        } elseif ($login === self::testValidUserWith2FA) {
            $user = new MockUser();
            $user->setLogin(self::testValidUserWith2FA);
            $user->setPassword($this->passwordProvider->encodePassword($user, self::testValidUserPasswordWith2FA, $this->salt));
            $user->setSalt($this->salt);
            $user->setTwoFactorAuthentication(true);
        }

        return $user;
    }

    public function getUserBy(array $params = []) : ?UserInterface
    {
        $user = null;
        if (isset($params['login'])) {
            if ($params['login'] === self::testValidUserName) {
                $user = new MockUser();
                $user->setLogin(self::testValidUserName);
                $user->setPassword($this->passwordProvider->encodePassword($user, self::testValidUserPassword, $this->salt));

                return $user;
            } elseif ($params['login'] === self::testValidUserWith2FA) {
                $user = new MockUser();
                $user->setLogin(self::testValidUserWith2FA);
                $user->setPassword($this->passwordProvider->encodePassword($user, self::testValidUserPasswordWith2FA, $this->salt));
                $user->setTwoFactorAuthentication(true);
            }
        }

        return $user;
    }
}