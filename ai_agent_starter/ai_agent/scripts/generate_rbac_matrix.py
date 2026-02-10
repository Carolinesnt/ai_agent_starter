import pandas as pd
import os

# Load data
roles = pd.read_csv('ai_agent/data/roles.csv')
permissions = pd.read_csv('ai_agent/data/permissions.csv')
# Be tolerant to filename variants: role_permissions.csv vs role_permission.csv
_rp_path = 'ai_agent/data/role_permissions.csv'
if not os.path.exists(_rp_path):
    _rp_path = 'ai_agent/data/role_permission.csv'
role_perms = pd.read_csv(_rp_path)

# Join tables
rbac = (role_perms
    .merge(roles[['role_id', 'role_name']], on='role_id')
    .merge(permissions[['permission_id', 'permission_code', 'permission_group', 'permission_desc']], 
           on='permission_id')
)

# Select columns for agent
rbac_matrix = rbac[['role_name', 'permission_code', 'permission_group', 'permission_desc']]

# Save
rbac_matrix.to_csv('ai_agent/data/rbac_matrix.csv', index=False)
print(f"✅ Generated rbac_matrix.csv ({len(rbac_matrix)} rows)")
