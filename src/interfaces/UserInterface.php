<?php
/**
 * This file is part of the EasySoft package.
 *
 * (c) Marcin Stodulski <marcin.stodulski@devsprint.pl>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace mstodulski\rbac\interfaces;

interface UserInterface {

    public function getLogin() : ?string;
    public function setLogin(string $login) : void;
    public function getPassword() : ?string;
    public function setPassword(string $password) : void;
    public function isInternalUser() : bool;
    public function isTwoFactorAuthentication() : bool;
}
