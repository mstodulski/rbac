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

interface UserProviderInterface  {

    public function getUser(string $login) : ?UserInterface;
    public function getUserBy(array $params = []) : ?UserInterface;
}
