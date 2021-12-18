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

interface AuthenticationResultHandlerInterface
{
    public function success(UserInterface $user);
    public function failed(string $login);
    public function secondStepFailed(string $login);
    public function secondStepTokenExpired(string $login);
}
