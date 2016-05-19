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
                'name' => 'Be banned',
                'slug' => 'be.banned',
            ]),
            'exacerbate' => Permission::create([
                'name' => 'Exacerbate',
                'slug' => 'exacerbate',
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
        $this->assertTrue($this->user->isOne($this->roles['admin']));
        $this->assertFalse($this->user->isOne($this->roles['manager']));

        $this->assertTrue($this->user->isAll([$this->roles['admin'], $this->roles['editor']]));
        $this->assertTrue($this->user->isAll([$this->roles['editor']]));
        $this->assertFalse($this->user->isAll([$this->roles['editor'], $this->roles['manager']]));
        $this->assertFalse($this->user->isAll($this->roles['manager']));
    }

    /**
     * @covers ::is
     */
    public function test_user_pretends()
    {
        Config::set('roles.pretend.enabled', false);
        $this->assertFalse($this->user->is($this->roles['manager']->slug));

        Config::set('roles.pretend.enabled', true);
        $this->assertTrue($this->user->is($this->roles['admin']->slug));
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

        $this->assertTrue($user->is($this->roles['manager']));
        $this->assertFalse($user->is($this->roles['admin']));

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
}