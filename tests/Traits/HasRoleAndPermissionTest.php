<?php

use Bican\Roles\Models\Permission;
use Bican\Roles\Models\Role;
use Illuminate\Foundation\Testing\DatabaseTransactions;

/**
 * @coversDefaultClass \Bican\Roles\Traits\HasRoleAndPermission
 */
class HasRoleAndPermissionTest extends TestCase
{

    use DatabaseTransactions;

    /**
     * @var \App\User
     */
    private $user;

    /**
     * @var Role[]
     */
    private $roles = [];

    /**
     * @var Permission[]
     */
    private $permissions = [];

    protected function setUp()
    {
        parent::setUp();

        $this->user = \App\User::create([
            'name'  => 'Some Name',
            'email' => 'some@email.com',
        ]);

        $this->roles = [
            'admin'   => Role::create([
                'name'  => 'Admin',
                'slug'  => 'admin',
                'level' => 2,
            ]),
            'editor'  => Role::create([
                'name'  => 'Editor',
                'slug'  => 'editor',
                'level' => 1,
            ]),
            'manager' => Role::create([
                'name' => 'Manager',
                'slug' => 'manager',
            ]),
        ];

        $this->permissions = [
            'see.page'   => Permission::create([
                'name' => 'See page',
                'slug' => 'see.page',
            ]),
            'be.banned'  => Permission::create([
                'name'  => 'Be banned',
                'slug'  => 'be.banned',
                'model' => \App\User::class,
            ]),
            'exacerbate' => Permission::create([
                'name' => 'Exacerbate',
                'slug' => 'exacerbate',
            ]),
            'unused'     => Permission::create([
                'name' => 'Unused',
                'slug' => 'unused',
            ]),
        ];

        $this->roles['admin']->attachPermission($this->permissions['see.page']);
        $this->roles['editor']->attachPermission($this->permissions['be.banned']);

        $this->user->userPermissions()->attach($this->permissions['exacerbate']);

        $this->user->attachRole($this->roles['admin']);
        $this->user->attachRole($this->roles['editor']);

        $this->user = $this->user->fresh(['roles']);
    }

    /**
     * @covers ::roles
     */
    public function test_has_roles_relation()
    {
        $this->assertInstanceOf(Role::class, $this->user->roles()->first());
    }

    /**
     * @covers ::getRoles
     */
    public function test_gets_roles()
    {
        $this->assertEquals(2, $this->user->getRoles()->count());
    }

    /**
     * @covers ::isOne
     * @covers ::isAll
     * @covers ::hasRole
     */
    public function test_checks_if_user_has_a_role()
    {
        $this->assertTrue($this->user->isOne($this->roles['admin']->slug));
        $this->assertTrue($this->user->isOne($this->roles['admin']->id));
        $this->assertFalse($this->user->isOne('manager'));

        $this->assertTrue($this->user->isAll('admin|editor'));
        $this->assertTrue($this->user->isAll('editor'));
        $this->assertFalse($this->user->isAll('editor, manager'));
        $this->assertFalse($this->user->isAll(['manager']));
    }

    /**
     * @covers ::is
     */
    public function test_user_pretends_role()
    {
        Config::set('roles.pretend.enabled', false);
        $this->assertFalse($this->user->is('manager'));

        Config::set('roles.pretend.enabled', true);
        $this->assertTrue($this->user->is('manager'));

        $this->assertTrue($this->user->is('admin'));
        Config::set('roles.pretend.options.is', false);
        $this->assertFalse($this->user->is('admin'));
    }

    /**
     * @covers ::attachRole
     */
    public function test_attaches_roles()
    {
        $user = \App\User::create([
            'name'  => 'Name',
            'email' => 'some2@email.com',
        ]);

        $this->assertNull($user->attachRole($this->roles['admin']));
        $user = $user->fresh('roles');
        $this->assertNull($user->attachRole($this->roles['manager']));
        $this->assertTrue($user->attachRole($this->roles['admin']));
    }

    /**
     * @covers ::detachRole
     * @covers ::detachAllRoles
     */
    public function test_detaches_roles()
    {
        $user = \App\User::create([
            'name'  => 'Name',
            'email' => 'some2@email.com',
        ]);

        $roles = Role::whereIn('slug', ['admin', 'manager'])->get();
        $user->roles()->attach($roles);
        $user->detachRole($this->roles['admin']);

        $this->assertTrue($user->is('manager'));
        $this->assertFalse($user->is('admin'));

        $user->detachAllRoles();
        $this->assertEmpty($user->roles);
    }

    /**
     * @covers ::level
     */
    public function test_gets_highest_level()
    {
        $this->assertEquals(2, $this->user->level());
        $this->user->detachRole($this->roles['admin']);
        $this->assertEquals(1, $this->user->level());
    }

    /**
     * @covers ::rolePermissions
     */
    public function test_gets_roles_permissions()
    {
        $this->assertEquals(2, $this->user->rolePermissions()->get()->count());
    }

    /**
     * @expectedException InvalidArgumentException
     * @covers ::rolePermissions
     */
    public function test_cant_set_not_model_as_permission_in_config()
    {
        Config::set('roles.models.permission', 'config');
        $this->user->rolePermissions();
    }

    /**
     * @covers ::userPermissions
     */
    public function test_has_user_permissions_relation()
    {
        $this->assertInstanceOf(Permission::class, $this->user->userPermissions()->first());
    }

    /**
     * @covers ::getPermissions
     */
    public function test_gets_user_and_roles_permissions()
    {
        $this->assertEquals(3, $this->user->getPermissions()->count());
    }

    /**
     * @covers ::can
     *
     * @covers ::getMethodName
     * @covers ::pretend
     * @covers ::isPretendEnabled
     */
    public function test_can_pretend_permission()
    {
        Config::set('roles.pretend.enabled', false);
        $this->assertFalse($this->user->can('unused'));

        Config::set('roles.pretend.enabled', true);
        $this->assertTrue($this->user->can('unused'));

        $this->assertTrue($this->user->can('admin'));
        Config::set('roles.pretend.options.can', false);
        $this->assertFalse($this->user->can('admin'));
    }

    /**
     * @covers ::canOne
     * @covers ::canAll
     * @covers ::hasPermission
     *
     * @covers ::getArrayFrom
     */
    public function test_checks_if_user_has_permission()
    {
        $this->assertTrue($this->user->canOne($this->permissions['see.page']->slug));
        $this->assertTrue($this->user->canOne($this->permissions['see.page']->id));
        $this->assertFalse($this->user->canOne('unused'));

        $this->assertTrue($this->user->canAll('see.page|be.banned'));
        $this->assertTrue($this->user->canAll('see.page'));
        $this->assertFalse($this->user->canAll('see.page, unused'));
        $this->assertFalse($this->user->canAll(['unused']));
    }

    /**
     * @covers ::hasRole
     * @covers ::hasPermission
     */
    public function test_permission_and_role_are_set_by_model()
    {
        $this->markTestSkipped('New pull request. Enable after resolution.');

        $this->assertTrue($this->user->isOne($this->roles['admin']));
        $this->assertTrue($this->user->canOne($this->permissions['see.page']));
    }

    /**
     * @covers ::allowed
     * @covers ::isAllowed
     */
    public function test_user_is_allowed_depending_on_rules()
    {
        $this->assertTrue($this->user->allowed('be.banned', $this->user));
        $this->assertFalse($this->user->allowed('see.page', $this->user));
    }

    /**
     * @covers ::allowed
     * @covers ::isAllowed
     */
    public function test_user_is_allowed_depending_on_ownership()
    {
        $user = \App\User::create(['name' => 'name2', 'email' => 'email2@email.com']);
        $this->assertTrue($user->allowed('be.banned', $user, true, 'id'));
        $this->assertFalse($user->allowed('be.banned', $this->user, true, 'id'));
    }

    /**
     * @covers ::allowed
     * @covers ::isAllowed
     */
    public function test_user_allowed_could_be_pretended()
    {
        Config::set('roles.pretend.enabled', false);
        $this->assertFalse($this->user->allowed('see.page', $this->user));
        Config::set('roles.pretend.enabled', true);
        $this->assertTrue($this->user->allowed('see.page', $this->user));
    }

    /**
     * @covers ::attachPermission
     */
    public function test_attaches_permissions()
    {
        $user = \App\User::create([
            'name'  => 'Name',
            'email' => 'some2@email.com',
        ]);

        $this->assertNull($user->attachPermission($this->permissions['be.banned']));
        $user = $user->fresh('userPermissions');
        $this->assertNull($user->attachPermission($this->permissions['see.page']));
        $this->assertTrue($user->attachPermission($this->permissions['be.banned']));
    }

    /**
     * @covers ::detachPermission
     * @covers ::detachAllPermissions
     */
    public function test_detaches_permissions()
    {
        $user = \App\User::create([
            'name'  => 'Name',
            'email' => 'some2@email.com',
        ]);

        $roles = Permission::whereIn('slug', ['be.banned', 'see.page'])->get();
        $user->userPermissions()->attach($roles);
        $user->detachPermission($this->permissions['see.page']);

        $this->assertTrue($user->can('be.banned'));
        $this->assertFalse($user->can('see.page'));

        $user->detachAllPermissions();
        $this->assertEmpty($user->userPermissions);
    }

    /**
     * @covers ::__call
     */
    public function test_magic_call()
    {
        $this->assertTrue($this->user->isAdmin());
        $this->assertFalse($this->user->isManager());

        $this->assertTrue($this->user->canBeBanned());
        $this->assertFalse($this->user->canUnused());

        $this->assertTrue($this->user->allowedBeBanned($this->user));
        $this->assertFalse($this->user->allowedUnused($this->user));

        $user = \App\User::create(['name' => 'name2', 'email' => 'email2@email.com']);
        $this->assertTrue($user->allowedBeBanned($user, true, 'id'));
    }

    /**
     * @covers ::__call
     */
    public function test_parent_call_works()
    {
        $this->user->getBindings();
    }
}