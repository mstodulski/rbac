<?php

use mstodulski\rbac\services\Authorization;
use PHPUnit\Framework\TestCase;

class Test extends TestCase
{
    private Authorization $authorization;
    private array $roles;
    
    public function setUp(): void
    {
        $this->authorization = new Authorization();
        [$this->roles, $permissions] = getRolesWithPermissions();
        $this->authorization->defineRoles(...$this->roles);
        $this->authorization->definePermissions(...$permissions);
        $this->authorization->processRolesAndPermissions();
    }

    public function testCheckSuperAdminPermissions()
    {
        $this->assertTrue($this->authorization->roleHasPermission($this->roles[4], 'DELETE_INVOICE_CATEGORY'));
        $this->assertTrue($this->authorization->roleHasPermission($this->roles[4], 'THIS_PERMISSION_NOT_EXISTS'));
        $this->assertTrue($this->authorization->roleHasPermission($this->roles[4], 'NOT_USED_PERMISSION'));
    }

    public function testAdminPermissions()
    {
        $this->assertTrue($this->authorization->roleHasPermission($this->roles[0], 'MANAGE_CUSTOMERS'));
        $this->assertTrue($this->authorization->roleHasPermission($this->roles[0], 'EDIT_CUSTOMER'));
        $this->assertTrue($this->authorization->roleHasPermission($this->roles[0], 'DELETE_CUSTOMER'));
        $this->assertTrue($this->authorization->roleHasPermission($this->roles[0], 'DEACTIVATE_CUSTOMER'));
        $this->assertTrue($this->authorization->roleHasPermission($this->roles[0], 'EDIT_INVOICE'));
        $this->assertTrue($this->authorization->roleHasPermission($this->roles[0], 'DELETE_INVOICE'));
        $this->assertTrue($this->authorization->roleHasPermission($this->roles[0], 'APPROVE_INVOICE'));
        $this->assertTrue($this->authorization->roleHasPermission($this->roles[0], 'SEND_INVOICE'));
        $this->assertTrue($this->authorization->roleHasPermission($this->roles[0], 'MANAGE_ARTICLES'));
        $this->assertTrue($this->authorization->roleHasPermission($this->roles[0], 'EDIT_ARTICLE'));
        $this->assertTrue($this->authorization->roleHasPermission($this->roles[0], 'DELETE_ARTICLE'));
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[0], 'MANAGE_INVOICE_CATEGORIES'));
        $this->assertTrue($this->authorization->roleHasPermission($this->roles[0], 'EDIT_INVOICE_CATEGORY'));
        $this->assertTrue($this->authorization->roleHasPermission($this->roles[0], 'DELETE_INVOICE_CATEGORY'));
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[0], 'DEACTIVATE_INVOICE_CATEGORY'));
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[0], 'NOT_USED_PERMISSION'));
    }

    public function testSupportPermissions()
    {
        $this->assertTrue($this->authorization->roleHasPermission($this->roles[1], 'MANAGE_CUSTOMERS'));
        $this->assertTrue($this->authorization->roleHasPermission($this->roles[1], 'EDIT_CUSTOMER'));
        $this->assertTrue($this->authorization->roleHasPermission($this->roles[1], 'DELETE_CUSTOMER'));
        $this->assertTrue($this->authorization->roleHasPermission($this->roles[1], 'DEACTIVATE_CUSTOMER'));
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[1], 'EDIT_INVOICE'));
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[1], 'DELETE_INVOICE'));
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[1], 'APPROVE_INVOICE'));
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[1], 'SEND_INVOICE'));
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[1], 'MANAGE_ARTICLES'));
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[1], 'EDIT_ARTICLE'));
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[1], 'DELETE_ARTICLE'));
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[1], 'MANAGE_INVOICE_CATEGORIES'));
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[1], 'EDIT_INVOICE_CATEGORY'));
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[1], 'DELETE_INVOICE_CATEGORY'));
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[1], 'DEACTIVATE_INVOICE_CATEGORY'));
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[1], 'NOT_USED_PERMISSION'));
    }

    public function testRedactorPermissions()
    {
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[2], 'MANAGE_CUSTOMERS'));
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[2], 'EDIT_CUSTOMER'));
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[2], 'DELETE_CUSTOMER'));
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[2], 'DEACTIVATE_CUSTOMER'));
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[2], 'EDIT_INVOICE'));
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[2], 'DELETE_INVOICE'));
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[2], 'APPROVE_INVOICE'));
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[2], 'SEND_INVOICE'));
        $this->assertTrue($this->authorization->roleHasPermission($this->roles[2], 'MANAGE_ARTICLES'));
        $this->assertTrue($this->authorization->roleHasPermission($this->roles[2], 'EDIT_ARTICLE'));
        $this->assertTrue($this->authorization->roleHasPermission($this->roles[2], 'DELETE_ARTICLE'));
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[2], 'MANAGE_INVOICE_CATEGORIES'));
        $this->assertTrue($this->authorization->roleHasPermission($this->roles[2], 'EDIT_INVOICE_CATEGORY'));
        $this->assertTrue($this->authorization->roleHasPermission($this->roles[2], 'DELETE_INVOICE_CATEGORY'));
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[2], 'DEACTIVATE_INVOICE_CATEGORY'));
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[2], 'NOT_USED_PERMISSION'));
    }

    public function testAccountantPermissions()
    {
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[3], 'MANAGE_CUSTOMERS'));
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[3], 'EDIT_CUSTOMER'));
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[3], 'DELETE_CUSTOMER'));
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[3], 'DEACTIVATE_CUSTOMER'));
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[3], 'MANAGE_ARTICLES'));
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[3], 'EDIT_ARTICLE'));
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[3], 'DELETE_ARTICLE'));
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[3], 'MANAGE_INVOICE_CATEGORIES'));
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[3], 'EDIT_INVOICE_CATEGORY'));
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[3], 'DELETE_INVOICE_CATEGORY'));
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[3], 'DEACTIVATE_INVOICE_CATEGORY'));
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[3], 'NOT_USED_PERMISSION'));
        $this->assertTrue($this->authorization->roleHasPermission($this->roles[3], 'MANAGE_INVOICES'));
        $this->assertTrue($this->authorization->roleHasPermission($this->roles[3], 'EDIT_INVOICE'));
        $this->assertTrue($this->authorization->roleHasPermission($this->roles[3], 'DELETE_INVOICE'));
        $this->assertTrue($this->authorization->roleHasPermission($this->roles[3], 'APPROVE_INVOICE'));
        $this->assertTrue($this->authorization->roleHasPermission($this->roles[3], 'SEND_INVOICE'));
    }

    public function testRedactorAssistantPermissions()
    {
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[5], 'MANAGE_CUSTOMERS'));
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[5], 'EDIT_CUSTOMER'));
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[5], 'DELETE_CUSTOMER'));
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[5], 'DEACTIVATE_CUSTOMER'));
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[5], 'EDIT_INVOICE'));
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[5], 'DELETE_INVOICE'));
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[5], 'APPROVE_INVOICE'));
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[5], 'SEND_INVOICE'));
        $this->assertTrue($this->authorization->roleHasPermission($this->roles[5], 'MANAGE_ARTICLES'));
        $this->assertTrue($this->authorization->roleHasPermission($this->roles[5], 'EDIT_ARTICLE'));
        $this->assertTrue($this->authorization->roleHasPermission($this->roles[5], 'DELETE_ARTICLE'));
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[5], 'MANAGE_INVOICE_CATEGORIES'));
        $this->assertTrue($this->authorization->roleHasPermission($this->roles[5], 'EDIT_INVOICE_CATEGORY'));
        $this->assertTrue($this->authorization->roleHasPermission($this->roles[5], 'DELETE_INVOICE_CATEGORY'));
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[5], 'DEACTIVATE_INVOICE_CATEGORY'));
        $this->assertFalse($this->authorization->roleHasPermission($this->roles[5], 'NOT_USED_PERMISSION'));
    }
}
