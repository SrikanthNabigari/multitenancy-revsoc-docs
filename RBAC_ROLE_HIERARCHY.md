# RBAC Role Hierarchy Design

## Overview
This document defines the role hierarchy system for the multi-tenant RBAC implementation. The hierarchy determines who can create users, assign roles, and manage tenants.

## Role Hierarchy Structure

### 1. Role Levels
```
Level 1: Super Admin (Platform Level)
Level 2: Owner (Tenant Level)
Level 3: Admin (Tenant Level)
Level 4: Analyst (Tenant Level)
Level 5: Viewer (Tenant Level)
```

### 2. Role Definitions

#### A. Super Admin (Platform Level)
- **Scope**: Entire platform
- **Level**: 1
- **Key Permissions**:
  - Create/manage all tenants
  - Create/manage users across all tenants
  - Assign any role including Super Admin
  - Access platform configuration
  - View platform analytics
  - Manage billing and subscriptions

#### B. Owner (Tenant Level)
- **Scope**: Specific tenant(s)
- **Level**: 2
- **Key Permissions**:
  - Full control over assigned tenant(s)
  - Create/manage users within tenant
  - Assign roles up to Owner level
  - Configure tenant settings
  - Manage tenant billing
  - Create sub-tenants (if hierarchical)
  - Delete tenant (with safeguards)

#### C. Admin (Tenant Level)
- **Scope**: Specific tenant(s)
- **Level**: 3
- **Key Permissions**:
  - Create/manage users within tenant
  - Assign roles up to Admin level
  - Manage data sources and connectors
  - Configure integrations
  - Manage tenant workflows
  - Cannot delete tenant
  - Cannot manage billing

#### D. Analyst (Tenant Level)
- **Scope**: Specific tenant(s)
- **Level**: 4
- **Key Permissions**:
  - View and analyze data
  - Create/modify reports and dashboards
  - Export data (with restrictions)
  - Cannot create users
  - Cannot manage configurations
  - Read-only access to settings

#### E. Viewer (Tenant Level)
- **Scope**: Specific tenant(s)
- **Level**: 5
- **Key Permissions**:
  - View dashboards and reports
  - Cannot modify anything
  - Cannot export data
  - Read-only access

## Permission Matrix

| Action | Super Admin | Owner | Admin | Analyst | Viewer |
|--------|------------|-------|-------|---------|--------|
| **Tenant Management** |
| Create Tenant | ✓ | ✗ | ✗ | ✗ | ✗ |
| Delete Tenant | ✓ | ✓* | ✗ | ✗ | ✗ |
| Modify Tenant Settings | ✓ | ✓ | ✗ | ✗ | ✗ |
| View Tenant Info | ✓ | ✓ | ✓ | ✓ | ✓ |
| **User Management** |
| Create Super Admin | ✓ | ✗ | ✗ | ✗ | ✗ |
| Create Owner | ✓ | ✗ | ✗ | ✗ | ✗ |
| Create Admin | ✓ | ✓ | ✗ | ✗ | ✗ |
| Create Analyst | ✓ | ✓ | ✓ | ✗ | ✗ |
| Create Viewer | ✓ | ✓ | ✓ | ✗ | ✗ |
| Modify User Roles | ✓ | ✓** | ✓** | ✗ | ✗ |
| Delete Users | ✓ | ✓ | ✓ | ✗ | ✗ |
| **Data Management** |
| Configure Data Sources | ✓ | ✓ | ✓ | ✗ | ✗ |
| View Data | ✓ | ✓ | ✓ | ✓ | ✓ |
| Export Data | ✓ | ✓ | ✓ | ✓*** | ✗ |
| Delete Data | ✓ | ✓ | ✓ | ✗ | ✗ |

\* Owner can only delete their own tenant
\** Can only assign roles at or below their level
\*** With restrictions and audit logging

## Role Assignment Rules

### 1. Hierarchical Assignment
```typescript
interface RoleAssignmentRule {
  canAssign(assignerRole: Role, targetRole: Role): boolean {
    // Super Admin can assign any role
    if (assignerRole.level === 1) return true;
    
    // Others can only assign roles at or below their level
    return assignerRole.level < targetRole.level;
  }
}
```

### 2. Cross-Tenant Assignment
- Super Admin: Can assign roles in any tenant
- Owner: Can only assign roles in their tenant(s)
- Admin: Can only assign roles in their tenant(s)
- Analyst/Viewer: Cannot assign roles

### 3. Self-Assignment Prevention
- Users cannot modify their own role
- Users cannot remove themselves from a tenant
- Last Owner/Admin protection (cannot remove if they're the last one)

## Implementation Details

### 1. Database Schema
```sql
-- Enhanced roles table
CREATE TABLE roles (
    id UUID PRIMARY KEY,
    role_name VARCHAR(50) UNIQUE NOT NULL,
    display_name VARCHAR(100) NOT NULL,
    description TEXT,
    level INTEGER NOT NULL, -- 1-5 hierarchy level
    scope VARCHAR(20) NOT NULL, -- 'platform' or 'tenant'
    is_system_role BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Role permissions mapping
CREATE TABLE role_permissions (
    id UUID PRIMARY KEY,
    role_id UUID NOT NULL,
    permission_id UUID NOT NULL,
    FOREIGN KEY (role_id) REFERENCES roles(id),
    FOREIGN KEY (permission_id) REFERENCES permissions(id),
    UNIQUE(role_id, permission_id)
);

-- Permissions table
CREATE TABLE permissions (
    id UUID PRIMARY KEY,
    permission_name VARCHAR(100) UNIQUE NOT NULL,
    resource VARCHAR(50) NOT NULL,
    action VARCHAR(50) NOT NULL,
    description TEXT
);
```

### 2. Permission Checking Logic
```typescript
class PermissionService {
  async canCreateUser(
    creator: User,
    creatorRole: Role,
    targetRole: Role,
    tenantId: string
  ): Promise<boolean> {
    // Super Admin can create anyone anywhere
    if (creatorRole.level === 1) return true;
    
    // Check if creator has access to the tenant
    const hasTenantAccess = await this.userHasTenantAccess(creator.id, tenantId);
    if (!hasTenantAccess) return false;
    
    // Check role hierarchy
    if (creatorRole.level >= targetRole.level) return false;
    
    // Check specific permission
    return this.hasPermission(creatorRole, 'USER_CREATE');
  }
  
  async canAssignRole(
    assigner: User,
    assignerRole: Role,
    targetUser: User,
    targetRole: Role,
    tenantId: string
  ): Promise<boolean> {
    // Cannot assign to self
    if (assigner.id === targetUser.id) return false;
    
    // Super Admin can assign any role
    if (assignerRole.level === 1) return true;
    
    // Check tenant access
    const hasTenantAccess = await this.userHasTenantAccess(assigner.id, tenantId);
    if (!hasTenantAccess) return false;
    
    // Check role hierarchy
    return assignerRole.level < targetRole.level;
  }
}
```

### 3. Tenant Creation Hierarchy
```typescript
interface TenantCreationRules {
  // Only Super Admin can create top-level tenants
  canCreateTenant(userRole: Role, parentTenantId?: string): boolean {
    if (!parentTenantId) {
      // Top-level tenant - only Super Admin
      return userRole.level === 1;
    }
    
    // Sub-tenant creation (if supported)
    // Owner of parent tenant can create sub-tenants
    return userRole.level <= 2;
  }
}
```

## Security Considerations

### 1. Privilege Escalation Prevention
- Users cannot assign roles higher than their own
- Role modifications are audit logged
- Dual approval for sensitive role assignments (optional)

### 2. Last Admin Protection
```typescript
async function removeUserFromTenant(userId: string, tenantId: string) {
  // Check if user is last admin/owner
  const admins = await getUsersWithRoleInTenant(tenantId, ['Owner', 'Admin']);
  
  if (admins.length === 1 && admins[0].id === userId) {
    throw new Error('Cannot remove last administrator from tenant');
  }
  
  // Proceed with removal
}
```

### 3. Audit Trail
All role assignments and modifications must be logged:
```typescript
interface RoleAuditLog {
  id: string;
  action: 'ASSIGN' | 'REVOKE' | 'MODIFY';
  performedBy: string;
  performedAt: Date;
  targetUser: string;
  previousRole?: string;
  newRole: string;
  tenantId: string;
  reason?: string;
}
```

## Migration Path for Existing System

1. **Phase 1**: Add level field to existing roles
2. **Phase 2**: Implement permission checking middleware
3. **Phase 3**: Update UI to respect role hierarchy
4. **Phase 4**: Migrate existing role assignments
5. **Phase 5**: Enable full RBAC enforcement