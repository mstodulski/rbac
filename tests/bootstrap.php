<?php

use mstodulski\rbac\entities\Permission;
use mstodulski\rbac\entities\Role;

require_once 'vendor/autoload.php';

function getRolesWithPermissions(): array
{
    $roles = [];

    $roleAdmin = new Role();
    $roleAdmin->setCode('ROLE_ADMIN');
    $roleAdmin->setName('Admin');

    $roleSupport = new Role();
    $roleSupport->setCode('ROLE_SUPPORT');
    $roleSupport->setName('Support');
    $roleSupport->setParent($roleAdmin);

    $roleRedactor = new Role();
    $roleRedactor->setCode('ROLE_REDACTOR');
    $roleRedactor->setName('Redactor');
    $roleRedactor->setParent($roleAdmin);

    $roleAccountant = new Role();
    $roleAccountant->setCode('ROLE_ACCOUNTANT');
    $roleAccountant->setName('Accountant');
    $roleAccountant->setParent($roleAdmin);

    $roleSuperadmin = new Role();
    $roleSuperadmin->setCode('ROLE_SUPERADMIN');
    $roleSuperadmin->setName('Superadmin');
    $roleSuperadmin->setHasAllPermissions(true); //should have all permissions

    $roleRedactorAssistant = new Role();
    $roleRedactorAssistant->setCode('ROLE_REDACTOR_ASSISTANT');
    $roleRedactorAssistant->setName('Redactor');
    $roleRedactorAssistant->setParent($roleRedactor);

    $permissionManageCustomers = new Permission();
    $permissionManageCustomers->setName('Manage customers');
    $permissionManageCustomers->setCode('MANAGE_CUSTOMERS');

    $permissionEditCustomer = new Permission();
    $permissionEditCustomer->setName('Edit customer');
    $permissionEditCustomer->setCode('EDIT_CUSTOMER');
    $permissionEditCustomer->setParent($permissionManageCustomers);

    $permissionDeleteCustomer = new Permission();
    $permissionDeleteCustomer->setName('Delete customer');
    $permissionDeleteCustomer->setCode('DELETE_CUSTOMER');
    $permissionDeleteCustomer->setParent($permissionManageCustomers);

    $permissionDeactivateCustomer = new Permission();
    $permissionDeactivateCustomer->setName('Deactivate customer');
    $permissionDeactivateCustomer->setCode('DEACTIVATE_CUSTOMER');
    $permissionDeactivateCustomer->setParent($permissionManageCustomers);

    $permissionManageInvoices = new Permission();
    $permissionManageInvoices->setName('Manage invoices');
    $permissionManageInvoices->setCode('MANAGE_INVOICES');

    $permissionEditInvoice = new Permission();
    $permissionEditInvoice->setName('Edit invoice');
    $permissionEditInvoice->setCode('EDIT_INVOICE');
    $permissionEditInvoice->setParent($permissionManageInvoices);

    $permissionDeleteInvoice = new Permission();
    $permissionDeleteInvoice->setName('Delete invoice');
    $permissionDeleteInvoice->setCode('DELETE_INVOICE');
    $permissionDeleteInvoice->setParent($permissionManageInvoices);

    $permissionApproveInvoice = new Permission();
    $permissionApproveInvoice->setName('Approve invoice');
    $permissionApproveInvoice->setCode('APPROVE_INVOICE');
    $permissionApproveInvoice->setParent($permissionManageInvoices);

    $permissionSendInvoice = new Permission();
    $permissionSendInvoice->setName('Send invoice');
    $permissionSendInvoice->setCode('SEND_INVOICE');

    $permissionManageArticles = new Permission();
    $permissionManageArticles->setName('Manage articles');
    $permissionManageArticles->setCode('MANAGE_ARTICLES');

    $permissionEditArticle = new Permission();
    $permissionEditArticle->setName('Edit article');
    $permissionEditArticle->setCode('EDIT_ARTICLE');
    $permissionEditArticle->setParent($permissionManageArticles);

    $permissionDeleteArticle = new Permission();
    $permissionDeleteArticle->setName('Delete article');
    $permissionDeleteArticle->setCode('DELETE_ARTICLE');
    $permissionDeleteArticle->setParent($permissionManageArticles);

    $permissionManageInvoiceCategories = new Permission();
    $permissionManageInvoiceCategories->setName('Manage invoice categories');
    $permissionManageInvoiceCategories->setCode('MANAGE_INVOICE_CATEGORIES');

    $permissionEditInvoiceCategory = new Permission();
    $permissionEditInvoiceCategory->setName('Edit invoice category');
    $permissionEditInvoiceCategory->setCode('EDIT_INVOICE_CATEGORY');
    $permissionEditInvoiceCategory->setParent($permissionManageInvoiceCategories);

    $permissionDeleteInvoiceCategory = new Permission();
    $permissionDeleteInvoiceCategory->setName('Delete invoice category');
    $permissionDeleteInvoiceCategory->setCode('DELETE_INVOICE_CATEGORY');
    $permissionDeleteInvoiceCategory->setParent($permissionManageInvoiceCategories);

    $permissionDeactivateInvoiceCategory = new Permission();
    $permissionDeactivateInvoiceCategory->setName('Deactivate invoice category');
    $permissionDeactivateInvoiceCategory->setCode('DEACTIVATE_INVOICE_CATEGORY');
    $permissionDeactivateInvoiceCategory->setParent($permissionManageInvoiceCategories);

    $permissionNotUsed = new Permission();
    $permissionNotUsed->setName('Not used permission');
    $permissionNotUsed->setCode('NOT_USED_PERMISSION');

    $roleSupport->addPermission($permissionManageCustomers); //should have MANAGE_CUSTOMERS, EDIT_CUSTOMER (child), DELETE_CUSTOMER (child), DEACTIVATE_CUSTOMER (child)

    $roleRedactorAssistant->addPermission($permissionManageArticles); //should have MANAGE_ARTICLES, EDIT_ARTICLE (child), DELETE_ARTICLE (child)
    $roleRedactorAssistant->addPermission($permissionEditInvoiceCategory); //should have EDIT_INVOICE_CATEGORY
    $roleRedactorAssistant->addPermission($permissionDeleteInvoiceCategory); //should have DELETE_INVOICE_CATEGORY

    $roleAccountant->addPermission($permissionManageInvoices); //should have MANAGE_INVOICES, EDIT_INVOICE (child), DELETE_INVOICE (child), APPROVE_INVOICE (child)
    $roleAccountant->addPermission($permissionSendInvoice); //should have SEND_INVOICE

    $roles[] = $roleAdmin;
    $roles[] = $roleSupport;
    $roles[] = $roleRedactor;
    $roles[] = $roleAccountant;
    $roles[] = $roleSuperadmin;
    $roles[] = $roleRedactorAssistant;

    $permissions[] = $permissionManageCustomers;
    $permissions[] = $permissionEditCustomer;
    $permissions[] = $permissionDeleteCustomer;
    $permissions[] = $permissionDeactivateCustomer;
    $permissions[] = $permissionManageInvoices;
    $permissions[] = $permissionEditInvoice;
    $permissions[] = $permissionDeleteInvoice;
    $permissions[] = $permissionApproveInvoice;
    $permissions[] = $permissionSendInvoice;
    $permissions[] = $permissionManageArticles;
    $permissions[] = $permissionEditArticle;
    $permissions[] = $permissionDeleteArticle;
    $permissions[] = $permissionManageInvoiceCategories;
    $permissions[] = $permissionEditInvoiceCategory;
    $permissions[] = $permissionDeleteInvoiceCategory;
    $permissions[] = $permissionDeactivateInvoiceCategory;


    return [$roles, $permissions];
}
