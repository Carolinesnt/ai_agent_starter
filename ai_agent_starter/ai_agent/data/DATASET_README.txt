Self-curated dataset for BYE BAC (Broken Access Control detection agent).
This dataset was created by the authors for the experimental REST API environment;
it is not from an internal ESS application, company backend, or production system.

Component files in this folder:
  - openapi.json       : API specification (endpoints, schemas)
  - roles.csv          : Master roles
  - permissions.csv    : Master permissions
  - role_permission.csv: Role–permission mapping
  - rbac_matrix.csv    : Flattened RBAC matrix (generated from above)

Full descriptive legend (sources, assembly, use in study):
  See docs/SELF_CURATED_DATASET_LEGEND.txt in the project root.

Policy and auth config (part of the same self-curated dataset):
  - ai_agent/config/policy.yaml
  - ai_agent/config/auth.yaml
