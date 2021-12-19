<?php

use mstodulski\rbac\entities\LoginStatus;
use mstodulski\rbac\services\Authenticator;
use mstodulski\rbac\services\Authorization;
use mstodulski\session\Session;
use PHPUnit\Framework\TestCase;
use test\helpers\MockTokenSender;
use test\helpers\MockTokenSenderWithCheckToken;
use test\helpers\MockUserProvider;

class Test extends TestCase
{
    private Authorization $authorization;
    private array $roles;
    const salt = 'saltsaltsalt';

    public function setUp(): void
    {
        $this->authorization = new Authorization();
        [$this->roles, $permissions] = getRolesWithPermissions();
        $this->authorization->defineRoles(...$this->roles);
        $this->authorization->definePermissions(...$permissions);
        $this->authorization->processRolesAndPermissions();
    }

    /** @throws Exception */
    public function testLoginSuccess()
    {
        $authenticator = new Authenticator(new MockUserProvider(), self::salt);
        $authenticator->logout();
        $authenticator->login(MockUserProvider::testValidUserName, MockUserProvider::testValidUserPassword);

        $this->assertEquals(LoginStatus::Logged, $authenticator->checkUserLoginStatus());
        $authenticator->logout();
        $this->assertEquals(LoginStatus::NotLogged, $authenticator->checkUserLoginStatus());
    }

    /** @throws Exception */
    public function testLoginFailedExistingUserBadPassword()
    {
        $authenticator = new Authenticator(new MockUserProvider(), self::salt);
        $authenticator->logout();
        $authenticator->login(MockUserProvider::testValidUserName, uniqid());
        $this->assertEquals(LoginStatus::NotLogged, $authenticator->checkUserLoginStatus());
    }

    /** @throws Exception */
    public function testLoginFailedNotExistingUser()
    {
        $authenticator = new Authenticator(new MockUserProvider(), self::salt);
        $authenticator->logout();
        $authenticator->login(uniqid('non_existing_user'), uniqid());
        $this->assertEquals(LoginStatus::NotLogged, $authenticator->checkUserLoginStatus());
    }

    public function testLoginSuccess2FATokenSenderNotExists()
    {
        $this->expectException(Exception::class);
        $authenticator = new Authenticator(new MockUserProvider(), self::salt);
        $authenticator->logout();
        $authenticator->login(MockUserProvider::testValidUserWith2FA, MockUserProvider::testValidUserPasswordWith2FA);
    }

    /** @throws Exception */
    public function testLoginSuccess2FA()
    {
        $authenticator = new Authenticator(new MockUserProvider(), self::salt, new MockTokenSender());
        $authenticator->logout();
        $loginResult = $authenticator->login(MockUserProvider::testValidUserWith2FA, MockUserProvider::testValidUserPasswordWith2FA);
        $this->assertEquals(LoginStatus::NeedSecondStep, $loginResult);
        $this->assertEquals(LoginStatus::NeedSecondStep, $authenticator->checkUserLoginStatus());

        $token = Session::getValueFromSession(Authenticator::_TOKEN_PATH, Authenticator::getSessionDataPaths());
        $authenticator->checkSecondFactor($token);
        $this->assertEquals(LoginStatus::Logged, $authenticator->checkUserLoginStatus());

        $authenticator->logout();
        $this->assertEquals(LoginStatus::NotLogged, $authenticator->checkUserLoginStatus());
    }

    /** @throws Exception */
    public function testLoginFailed2FA()
    {
        $authenticator = new Authenticator(new MockUserProvider(), self::salt, new MockTokenSender());
        $authenticator->logout();
        $loginStatus = $authenticator->login(MockUserProvider::testValidUserWith2FA, MockUserProvider::testValidUserPasswordWith2FA);
        $this->assertEquals(LoginStatus::NeedSecondStep, $loginStatus);
        $this->assertEquals(LoginStatus::NeedSecondStep, $authenticator->checkUserLoginStatus());

        $token = uniqid('bad_token');
        $result = $authenticator->checkSecondFactor($token);
        $this->assertEquals(LoginStatus::TokenIncorrect, $result);
        $this->assertEquals(LoginStatus::NeedSecondStep, $authenticator->checkUserLoginStatus());
    }

    /** @throws Exception */
    public function testLoginSuccess2FAWithCheckToken()
    {
        $authenticator = new Authenticator(new MockUserProvider(), self::salt, new MockTokenSenderWithCheckToken());
        $authenticator->logout();
        $authenticator->login(MockUserProvider::testValidUserWith2FA, MockUserProvider::testValidUserPasswordWith2FA);
        $this->assertEquals(LoginStatus::NeedSecondStep, $authenticator->checkUserLoginStatus());

        $token = Session::getValueFromSession(Authenticator::_TOKEN_PATH, Authenticator::getSessionDataPaths());
        $authenticator->checkSecondFactor($token);
        $this->assertEquals(LoginStatus::Logged, $authenticator->checkUserLoginStatus());

        $authenticator->logout();
        $this->assertEquals(LoginStatus::NotLogged, $authenticator->checkUserLoginStatus());
    }

    public function testHardLoginIfNotLoggedWithout2FA()
    {
        $authenticator = new Authenticator(new MockUserProvider(), self::salt, new MockTokenSender());
        $authenticator->logout();
        $authenticator->hardLoginByUserLogin(MockUserProvider::testValidUserName);
        $this->assertEquals(LoginStatus::Logged, $authenticator->checkUserLoginStatus());
    }

    public function testHardLoginIfNotLoggedWith2FA()
    {
        $authenticator = new Authenticator(new MockUserProvider(), self::salt, new MockTokenSender());
        $authenticator->logout();
        $authenticator->hardLoginIfNotLogged(MockUserProvider::testValidUserWith2FA);
        $this->assertEquals(LoginStatus::Logged, $authenticator->checkUserLoginStatus());

        $loggedUser = Authenticator::getLoggedUser();
        $this->assertEquals(MockUserProvider::testValidUserWith2FA, $loggedUser->getLogin());

    }

    /** @throws Exception */
    public function testLoginWith2FATokenExpired()
    {
        $authenticator = new Authenticator(new MockUserProvider(), self::salt, new MockTokenSender());
        $authenticator->logout();
        $loginStatus = $authenticator->login(
            MockUserProvider::testValidUserWith2FA,
            MockUserProvider::testValidUserPasswordWith2FA,
            false,
            1
        );
        $this->assertEquals(LoginStatus::NeedSecondStep, $loginStatus);
        $this->assertEquals(LoginStatus::NeedSecondStep, $authenticator->checkUserLoginStatus());

        sleep(2);

        $token = Session::getValueFromSession(Authenticator::_TOKEN_PATH, Authenticator::getSessionDataPaths());
        $checkSecondFactorStatus = $authenticator->checkSecondFactor($token);
        $this->assertEquals(LoginStatus::TokenExpired, $checkSecondFactorStatus);
        $this->assertEquals(LoginStatus::NotLogged, $authenticator->checkUserLoginStatus());
    }

    /** @throws Exception */
    public function testLoginWith2FATokenExpiredGetLoginStatus()
    {
        $authenticator = new Authenticator(new MockUserProvider(), self::salt, new MockTokenSender());
        $authenticator->logout();
        $loginStatus = $authenticator->login(
            MockUserProvider::testValidUserWith2FA,
            MockUserProvider::testValidUserPasswordWith2FA,
            false,
            1
        );
        $this->assertEquals(LoginStatus::NeedSecondStep, $loginStatus);
        $this->assertEquals(LoginStatus::NeedSecondStep, $authenticator->checkUserLoginStatus());

        sleep(2);
        $this->assertEquals(LoginStatus::NotLogged, $authenticator->checkUserLoginStatus());
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
