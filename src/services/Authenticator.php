<?php
/**
 * This file is part of the EasySoft package.
 *
 * (c) Marcin Stodulski <marcin.stodulski@devsprint.pl>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace mstodulski\rbac\services;

use DateInterval;
use DateTime;
use Exception;
use mstodulski\rbac\interfaces\TokenSenderInterface;
use mstodulski\rbac\interfaces\UserInterface;
use mstodulski\rbac\interfaces\UserProviderInterface;
use mstodulski\session\Session;

class Authenticator {

    const _AUTHORIZATION_DATA_PATH = 0;
    const _LOGGED_USER_LOGIN_PATH = 1;
    const _PASSWORD_HASH_PATH = 2;
    const _USER = 3;
    const _TOKEN_PATH = 4;
    const _TOKEN_EXPIRATION_DATE_PATH = 5;
    const _TOKEN_LOGIN = 6;
    const _SECOND_STEP = 7;

    const _LOGIN_STATUS_NOT_LOGGED = 0;
    const _LOGIN_STATUS_LOGGED = 1;
    const _LOGIN_STATUS_NEED_SECOND_STEP = 2;
    const _LOGIN_STATUS_TOKEN_INCORRECT = 3;
    const _LOGIN_STATUS_TOKEN_EXPIRED = 4;

    private ?UserProviderInterface $userProvider;
    private ?TokenSenderInterface $tokenSender;

    public static function getSessionDataPaths(): array
    {
        return array(
            0 => 'authentication',
            1 => 'authentication/loggedUserLogin',
            2 => 'authentication/passwordHash',
            3 => 'authentication/user',
            4 => 'authentication/secondStep/token',
            5 => 'authentication/secondStep/expiration',
            6 => 'authentication/secondStep/login',
            7 => 'authentication/secondStep',
        );
    }

    public function __construct(UserProviderInterface $userProvider, TokenSenderInterface $tokenSender = null)
    {
        $this->userProvider = $userProvider;
        $this->tokenSender = $tokenSender;
    }

    private function saveLoggedUserData(UserInterface $user, bool $rememberMe)
    {
        if (!$user->isInternalUser()) {
            Session::removeValueFromSession(self::_SECOND_STEP, self::getSessionDataPaths());
        }
        Session::saveValueToSession(self::_LOGGED_USER_LOGIN_PATH, $user->getLogin(), self::getSessionDataPaths());
        Session::saveValueToSession(self::_PASSWORD_HASH_PATH, md5($user->getPassword()), self::getSessionDataPaths());
        Session::saveValueToSession(self::_USER, $user, self::getSessionDataPaths());

        if ($rememberMe) {
            setcookie('loggedIn', md5($user->getPassword() . $user->getLogin()), time() + (7 * 24 * 3600), '/');
        }
    }

    private function generateToken(UserInterface $user) : string
    {
        $token = rand(100000, 999999);

        $currentDateTime = new DateTime();
        $currentDateTime->add(new DateInterval('PT5M'));

        Session::saveValueToSession(self::_TOKEN_PATH, $token, self::getSessionDataPaths());
        Session::saveValueToSession(self::_TOKEN_EXPIRATION_DATE_PATH, $currentDateTime->format('Y-m-d H:i:s'), self::getSessionDataPaths());
        Session::saveValueToSession(self::_TOKEN_LOGIN, $user->getLogin(), self::getSessionDataPaths());

        return $token;
    }

    /** @throws Exception */
    private function sendTokenToUser(UserInterface $user)
    {
        if (null !== $this->tokenSender) {
            $token = $this->generateToken($user);
            $this->tokenSender->sendToken($user, $token);
        } else {
            throw new Exception('Authenticator does not have configured TokenSender');
        }
    }

    /** @throws Exception */
    public function checkSecondFactor(string $userToken, bool $rememberMe = false): int
    {
        $token = Session::getValueFromSession(Authenticator::_TOKEN_PATH, Authenticator::getSessionDataPaths());
        $date = Session::getValueFromSession(Authenticator::_TOKEN_EXPIRATION_DATE_PATH, Authenticator::getSessionDataPaths());
        $login = Session::getValueFromSession(self::_TOKEN_LOGIN, self::getSessionDataPaths());

        if (!method_exists($this->tokenSender, 'checkToken')) {
            $expirationDate = new DateTime($date);
            $now = new DateTime();

            if ($expirationDate < $now) {
                return self::_LOGIN_STATUS_TOKEN_EXPIRED;
            } else {
                if ($userToken != $token) {
                    return self::_LOGIN_STATUS_TOKEN_INCORRECT;
                } else {
                    $user = $this->userProvider->getUser($login);
                    $this->saveLoggedUserData($user, $rememberMe);
                    return self::_LOGIN_STATUS_LOGGED;
                }
            }
        } else {
            $user = $this->userProvider->getUser($login);
            if ($this->tokenSender->checkToken($user, $userToken)) {
                $this->saveLoggedUserData($user, $rememberMe);
                return self::_LOGIN_STATUS_LOGGED;
            }
        }

        return self::_LOGIN_STATUS_NOT_LOGGED;
    }

    /** @throws Exception */
    public function login(string $login, string $password, bool $rememberMe = false): int
    {
        $user = $this->userProvider->getUser($login);
        if (null !== $user) {
            $passwordProvider = new PasswordProvider();
            $res = $passwordProvider->checkPassword($user, $password);

            if (!$res) {
                return self::_LOGIN_STATUS_NOT_LOGGED;
            } else {
                if ($user->isTwoFactorAuthentication() && ($this->tokenSender !== null)) {
                    $this->sendTokenToUser($user);
                    return self::_LOGIN_STATUS_NEED_SECOND_STEP;
                } else {
                    $this->saveLoggedUserData($user, $rememberMe);
                    return self::_LOGIN_STATUS_LOGGED;
                }
            }

        } else {
            return self::_LOGIN_STATUS_NOT_LOGGED;
        }
    }

    public function hardLoginByUserLogin(string $login): int
    {
        $user = $this->userProvider->getUser($login);
        $this->saveLoggedUserData($user, false);
        return self::_LOGIN_STATUS_LOGGED;
    }

    public function checkUserLoginStatus(): int
    {
        $login = Session::getValueFromSession(self::_LOGGED_USER_LOGIN_PATH, self::getSessionDataPaths());

        if ($login === null) {
            return self::_LOGIN_STATUS_NOT_LOGGED;
        }

        $user = $this->userProvider->getUser($login);

        if ($user->getLogin() !== null) {
            if (md5($user->getPassword()) == Session::getValueFromSession(self::_PASSWORD_HASH_PATH, self::getSessionDataPaths())) {
                return self::_LOGIN_STATUS_LOGGED;
            } else {
                $this->logout();
                return self::_LOGIN_STATUS_NOT_LOGGED;
            }
        } else {
            $this->logout();
            return self::_LOGIN_STATUS_NOT_LOGGED;
        }
    }

    public static function getLoggedUser(): ?UserInterface
    {
        /** @noinspection */
        return Session::getValueFromSession(self::_USER, self::getSessionDataPaths());
    }

    public function logout()
    {
        Session::removeValueFromSession(self::_AUTHORIZATION_DATA_PATH, self::getSessionDataPaths());
        setcookie('logged', '', time() - 3600, '/');
    }

    public function hardLoginIfNotLogged($login): bool
    {
        $hardLogged = false;
        $loginStatus = $this->checkUserLoginStatus();

        if ($loginStatus !== Authenticator::_LOGIN_STATUS_LOGGED) {
            $this->hardLoginByUserLogin($login);
            $hardLogged = true;
        }

        return $hardLogged;
    }
}
