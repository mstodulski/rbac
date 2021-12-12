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

use mstodulski\rbac\interfaces\PermissionInterface;
use mstodulski\rbac\interfaces\RoleInterface;

class Authorization {

    private array $roles = [];
    private array $permissions = [];
    private array $rolesTree = [];
    private array $permissionsTree = [];
    private array $permissionsForRoles = [];

    public function defineRoles(RoleInterface ...$roles)
    {
        $this->roles = $roles;
    }

    public function definePermissions(PermissionInterface ...$permissions)
    {
        $this->permissions = $permissions;
    }

    public function processRolesAndPermissions()
    {
        $this->rolesTree = $this->buildTree($this->roles);
        $this->permissionsTree = $this->buildTree($this->permissions);
    }

    public function roleHasPermission(RoleInterface $role, $permissionCode): bool
    {
        if ($role->isHasAllPermissions()) {
            return true;
        } else {
            if (isset($this->permissionsForRoles[$role->getCode()])) {
                $permissionsArray = $this->permissionsForRoles[$role->getCode()];
            } else {
                [, $permissionsArray] = $this->getAllSubRolesAndPermissionsForRole($role);
                $this->permissionsForRoles[$role->getCode()] = $permissionsArray;
            }

            return in_array($permissionCode, $permissionsArray);
        }
    }

    public function setPermissionsForRoles(array $permissionsForRoles): void
    {
        $this->permissionsForRoles = $permissionsForRoles;
    }

    public function getAllSubRolesAndPermissionsForRole(RoleInterface $role): array
    {
        $rolesArray = [$role->getCode()];
        $permissionsArray = [];
        $this->getSubRolesCodes($rolesArray, $permissionsArray, $this->rolesTree);
        $this->getSubPermissionsForPermissions($permissionsArray, $this->permissionsTree);

        return [$rolesArray, $permissionsArray];
    }

    private function getSubPermissionsForPermissions(&$permissionsArray, $permissionsTree = null)
    {
        /** @var PermissionInterface $permission */
        foreach ($permissionsTree as $permission) {
            if (in_array($permission->getCode(), $permissionsArray)) {
                if (isset($permission->children)) {
                    /** @var PermissionInterface $childPermission */
                    foreach ($permission->children as $childPermission) {
                        $permissionsArray[$childPermission->getCode()] = $childPermission->getCode();
                    }
                }
            }

            if (isset($permission->children)) {
                $this->getSubPermissionsForPermissions($permissionsArray, $permission->children);
            }
        }
    }

    private function getSubRolesCodes(&$rolesArray, &$permissionsArray, $rolesTree = null)
    {
        /** @var RoleInterface $role */
        foreach ($rolesTree as $role) {
            if (in_array($role->getCode(), $rolesArray)) {
                foreach ($role->getPermissions() as $permission) {
                    $permissionsArray[$permission->getCode()] = $permission->getCode();
                }

                if (isset($role->children)) {
                    /** @var RoleInterface $childRole */
                    foreach ($role->children as $childRole) {
                        $rolesArray[] = $childRole->getCode();
                        foreach ($childRole->getPermissions() as $permission) {
                            $permissionsArray[$permission->getCode()] = $permission->getCode();
                        }
                    }
                }
            }

            if (isset($role->children)) {
                $this->getSubRolesCodes($rolesArray, $permissionsArray, $role->children);
            }
        }
    }

    private function buildTree(array $elements, $parentId = null): array
    {
        $branch = array();

        /** @var RoleInterface|PermissionInterface $element */
        foreach ($elements as $element) {
            $elementParentId = ($element->getParent() !== null) ? $element->getParent()->getCode() : null;
            if ($elementParentId == $parentId) {
                $children = $this->buildTree($elements, $element->getCode());
                if ($children) {
                    $element->children = $children;
                }
                $branch[] = $element;
            }
        }

        return $branch;
    }
}
