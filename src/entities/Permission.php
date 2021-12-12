<?php
/**
 * This file is part of the EasySoft package.
 *
 * (c) Marcin Stodulski <marcin.stodulski@devsprint.pl>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace mstodulski\rbac\entities;

use mstodulski\rbac\interfaces\PermissionInterface;

class Permission implements PermissionInterface
{
    private ?self $parent = null;
    private string $code = '';
    private string $name = '';

    public function setCode(string $code): void
    {
        $this->code = $code;
    }

    public function getCode(): string
    {
        return $this->code;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function setName(string $name): void
    {
        $this->name = $name;
    }

    public function getParent(): ?PermissionInterface
    {
        return $this->parent;
    }

    public function setParent(?PermissionInterface $parent): void
    {
        $this->parent = $parent;
    }
}
