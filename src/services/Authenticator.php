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
use mstodulski\rbac\entities\LoginStatus;
use mstodulski\rbac\interfaces\AuthenticationResultHandlerInterface;
use mstodulski\rbac\interfaces\TokenSenderInterface;
use mstodulski\rbac\interfaces\UserInterface;
use mstodulski\rbac\interfaces\UserProviderInterface;
use mstodulski\session\Session;

class Authenticator
{
    const _AUTHORIZATION_DATA_PATH = 0;
    const _LOGGED_USER_LOGIN_PATH = 1;
    const _PASSWORD_HASH_PATH = 2;
    const _USER = 3;
    const _TOKEN_PATH = 4;
    const _TOKEN_EXPIRATION_DATE_PATH = 5;
    const _TOKEN_LOGIN = 6;
    const _SECOND_STEP = 7;

    private ?UserProviderInterface $userProvider;
    private ?TokenSenderInterface $tokenSender;
    private ?AuthenticationResultHandlerInterface $authenticationResultHandler;

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

    public function __construct(
        UserProviderInterface $userProvider,
        TokenSenderInterface $tokenSender = null,
        AuthenticationResultHandlerInterface $authenticationResultHandler = null
    ) {
        $this->userProvider = $userProvider;
        $this->tokenSender = $tokenSender;
        $this->authenticationResultHandler = $authenticationResultHandler;
    }

    /** @throws Exception */
    public function login(string $login, string $password, bool $rememberMe = false, int $expirationSeconds = null): LoginStatus
    {
        $user = $this->userProvider->getUser($login);

        if (null !== $user) {
            $passwordProvider = new PasswordProvider();
            $res = $passwordProvider->checkPassword($user, $password);

            if (!$res) {
                $this->authenticationResultHandler?->failed($login);
                return LoginStatus::NotLogged;
            } else {
                if ($user->isTwoFactorAuthentication()) {
                    if ($this->tokenSender === null) {
                        throw new Exception('Second factor token sender not defined');
                    }

                    $this->sendTokenToUser($user, $expirationSeconds);
                    return LoginStatus::NeedSecondStep;
                } else {
                    $this->saveLoggedUserData($user, $rememberMe);
                    $this->authenticationResultHandler?->success($user);
                    return LoginStatus::Logged;
                }
            }

        } else {
            $this->authenticationResultHandler?->failed($login);
            return LoginStatus::NotLogged;
        }
    }

    public function logout() : void
    {
        Session::removeValueFromSession(self::_AUTHORIZATION_DATA_PATH, self::getSessionDataPaths());
        if (isset($_COOKIE['logged'])) {
            setcookie('logged', '', time() - 3600, '/');
        }
    }

    /** @throws Exception */
    public function checkSecondFactor(string $userToken, bool $rememberMe = false): LoginStatus
    {
        $token = Session::getValueFromSession(Authenticator::_TOKEN_PATH, Authenticator::getSessionDataPaths());
        $date = Session::getValueFromSession(Authenticator::_TOKEN_EXPIRATION_DATE_PATH, Authenticator::getSessionDataPaths());
        $login = Session::getValueFromSession(self::_TOKEN_LOGIN, self::getSessionDataPaths());

        if (!method_exists($this->tokenSender, 'checkToken')) {
            $expirationDate = new DateTime($date);
            $now = new DateTime();

            if ($expirationDate < $now) {
                $this->authenticationResultHandler?->secondStepTokenExpired($login);
                self::logout();
                return LoginStatus::TokenExpired;
            } else {
                if ($userToken != $token) {
                    $this->authenticationResultHandler?->secondStepFailed($login);
                    return LoginStatus::TokenIncorrect;
                } else {
                    $user = $this->userProvider->getUser($login);
                    $this->saveLoggedUserData($user, $rememberMe);
                    $this->authenticationResultHandler?->success($user);
                    return LoginStatus::Logged;
                }
            }
        } else {
            $user = $this->userProvider->getUser($login);
            if ($this->tokenSender->checkToken($user, $userToken)) {
                $this->saveLoggedUserData($user, $rememberMe);
                $this->authenticationResultHandler?->success($user);
                return LoginStatus::Logged;
            } else {
                $this->authenticationResultHandler?->secondStepFailed($login);
                return LoginStatus::TokenIncorrect;
            }
        }
    }

    public function hardLoginByUserLogin(string $login): LoginStatus
    {
        $user = $this->userProvider->getUser($login);
        $this->saveLoggedUserData($user, false);
        $this->authenticationResultHandler?->success($user);
        return LoginStatus::Logged;
    }

    public function checkUserLoginStatus(): LoginStatus
    {
        $login = Session::getValueFromSession(self::_LOGGED_USER_LOGIN_PATH, self::getSessionDataPaths());
        $secondFactorExpirationDate = Session::getValueFromSession(self::_TOKEN_EXPIRATION_DATE_PATH, self::getSessionDataPaths());

        if (($login === null) && ($secondFactorExpirationDate === null)) {
            self::logout();
            return LoginStatus::NotLogged;
        } elseif ($secondFactorExpirationDate !== null) {
            if (strtotime($secondFactorExpirationDate) < time()) {
                Session::removeValueFromSession(self::_TOKEN_PATH, self::getSessionDataPaths());
                return LoginStatus::NotLogged;
            } else {
                return LoginStatus::NeedSecondStep;
            }
        }

        $user = $this->userProvider->getUser($login);

        if ($user->getLogin() !== null) {
            if (md5($user->getPassword()) == Session::getValueFromSession(self::_PASSWORD_HASH_PATH, self::getSessionDataPaths())) {
                $this->authenticationResultHandler?->success($user);
                return LoginStatus::Logged;
            } else {
                self::logout();
                return LoginStatus::NotLogged;
            }
        } else {
            self::logout();
            return LoginStatus::NotLogged;
        }
    }

    public static function getLoggedUser(): ?UserInterface
    {
        /** @noinspection */
        return Session::getValueFromSession(self::_USER, self::getSessionDataPaths());
    }

    public function hardLoginIfNotLogged($login): bool
    {
        $hardLogged = false;
        $loginStatus = $this->checkUserLoginStatus();

        if ($loginStatus !== LoginStatus::Logged) {
            $this->hardLoginByUserLogin($login);
            $hardLogged = true;
        }

        return $hardLogged;
    }

    private function saveLoggedUserData(UserInterface $user, bool $rememberMe) : void
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

    /** @throws Exception */
    private function generateToken(UserInterface $user, int $expirationSeconds = null) : string
    {
        $token = rand(100000, 999999);

        $currentDateTime = new DateTime();
        if ($expirationSeconds !== null) {
            $currentDateTime->add(new DateInterval('PT' . $expirationSeconds . 'S'));
        } else {
            $currentDateTime->add(new DateInterval('PT5M'));
        }

        Session::saveValueToSession(self::_TOKEN_PATH, $token, self::getSessionDataPaths());
        Session::saveValueToSession(self::_TOKEN_EXPIRATION_DATE_PATH, $currentDateTime->format('Y-m-d H:i:s'), self::getSessionDataPaths());
        Session::saveValueToSession(self::_TOKEN_LOGIN, $user->getLogin(), self::getSessionDataPaths());

        return $token;
    }

    /**@throws Exception */
    private function sendTokenToUser(UserInterface $user, $expirationSeconds = null) : void
    {
        $token = $this->generateToken($user, $expirationSeconds);
        $this->tokenSender->sendToken($user, $token);
    }
}
