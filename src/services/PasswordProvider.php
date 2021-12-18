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

use mstodulski\rbac\interfaces\UserInterface;

class PasswordProvider {

    private string $hashAlgorithm;

    public function __construct(string $hashAlgorithm = 'sha256')
    {
        $this->hashAlgorithm = $hashAlgorithm;
    }

    public function encodePassword(UserInterface $user, $password, $salt = null): string
    {
        $newPassword = $password . sha1($user->getLogin()) . $salt;
        return hash($this->hashAlgorithm, $newPassword);
    }

    public function checkPassword(UserInterface $user, $password): bool
    {
        $hash = $this->encodePassword($user, $password, $user->getSalt());
        return ($user->getPassword() === $hash);
    }
}
