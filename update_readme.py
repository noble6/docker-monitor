import re

with open('README.md', 'r') as f:
    content = f.read()

appendix = """
## Policy-as-Code (OPA) Integration

This project integrates **Open Policy Agent (OPA)** directly into the CI pipeline to enforce container security standards automatically. It doesn't just report issues—it fails the build if security policies are violated.

### How it works in the pipeline
1. The CI pipeline runs `audit.py`.
2. `audit.py` performs its usual multi-engine vulnerability scan and container structure inspection.
3. The resulting aggregated JSON report is fed into `policy_evaluator.py`, which invokes the `opa` CLI against our `.rego` policies.
4. If violations are detected, the OPA evaluator outputs them, flags the build as `FAILED`, and causes `audit.py` to exit non-zero, immediately failing the CI/CD job.
5. The policy results are then surfaced on the CyberSec Dashboard for visibility.

### How to add a new Rego policy
All policies are defined in `policies/security.rego`. To add a new rule:
1. Open `policies/security.rego`.
2. Add a new `violations[msg]` block. 
3. The input format maps directly to `reports/latest_multi_engine_summary.json`. 
4. Check for exception overrides (e.g. `not is_exception(image_key, "my_new_rule")`).
5. Assign a descriptive violation message to `msg`.

Example:
```rego
violations[msg] {
    some image_key
    image_data := input[image_key]
    not is_exception(image_key, "deny_alpine")
    
    # Custom rule logic
    startswith(image_data.config.Image, "alpine")
    msg := sprintf("[%s] deny_alpine: Alpine images are restricted", [image_key])
}
```

### Exceptions File (`policy-exceptions.yml`)
You can suppress specific rules for specific images without ignoring the whole policy engine. 
Edit `policy-exceptions.yml` to specify the exception, a documented reason, and an expiry date.

```yaml
exceptions:
  hardened:
    deny_no_resource_limits:
      reason: "Resource limits are managed externally by Kubernetes."
      expiry: "2030-01-01"
```

### Worked Example: CI Pipeline Failure

Below is an actual CI execution log showing the pipeline actively failing due to non-compliant container configurations:

```text
=== Policy-as-Code Evaluation (OPA) ===
CI Build Failed: Policy violations detected!
 - [hardened] deny_critical_cve: Contains 6 critical CVEs
 - [hardened] deny_latest_tag: Image uses the ':latest' tag (flask-app-hardened:latest)
 - [hardened] deny_latest_tag: Image uses the ':latest' tag (hardened-image:latest)
 - [hardened] deny_latest_tag: Image uses the ':latest' tag (test-hardened-image:latest)
 - [vulnerable] deny_critical_cve: Contains 18 critical CVEs
 - [vulnerable] deny_latest_tag: Image uses the ':latest' tag (docker-monitor-vuln:latest)
 - [vulnerable] deny_latest_tag: Image uses the ':latest' tag (flask-app-vulnerable:latest)
 - [vulnerable] deny_latest_tag: Image uses the ':latest' tag (vulnerable-image:latest)
 - [vulnerable] deny_no_resource_limits: No resource limits defined in configuration
 - [vulnerable] deny_root_user: Container runs as root (no User directive)
```
"""

with open('README.md', 'w') as f:
    f.write(content + "\n" + appendix)
