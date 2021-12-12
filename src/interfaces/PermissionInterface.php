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

use mstodulski\rbac\entities\Role;

interface PermissionInterface
{
    public function getParent(): ?PermissionInterface;
    public function getCode(): string;
}
