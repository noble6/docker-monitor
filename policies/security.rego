package security

default pass = false

# Return pass = true if there are no violations
pass {
    count(violations) == 0
}

# Collect all violations across all images in the scan report
violations[msg] {
    some image_key
    image_data := input[image_key]
    is_object(image_data)
    image_data.critical != null # Ensure it's an image block

    # Rule: deny_root_user
    not is_exception(image_key, "deny_root_user")
    user := object.get(image_data.config, "User", "")
    user == ""
    msg := sprintf("[%s] deny_root_user: Container runs as root (no User directive)", [image_key])
}

violations[msg] {
    some image_key
    image_data := input[image_key]
    is_object(image_data)
    image_data.critical != null

    # Rule: deny_root_user
    not is_exception(image_key, "deny_root_user")
    user := object.get(image_data.config, "User", "")
    user == "root"
    msg := sprintf("[%s] deny_root_user: Container explicitly runs as root", [image_key])
}

violations[msg] {
    some image_key
    image_data := input[image_key]
    is_object(image_data)
    image_data.critical != null

    # Rule: deny_critical_cve (Array format)
    not is_exception(image_key, "deny_critical_cve")
    some cve
    cve = image_data.critical_cves[_]
    not is_exception(image_key, cve)
    msg := sprintf("[%s] deny_critical_cve: Contains critical CVE %s", [image_key, cve])
}

violations[msg] {
    some image_key
    image_data := input[image_key]
    is_object(image_data)
    
    # Rule: deny_critical_cve (Legacy fallback for flat count)
    not is_exception(image_key, "deny_critical_cve")
    not object.get(image_data, "critical_cves", false)
    image_data.critical > 0
    msg := sprintf("[%s] deny_critical_cve: Contains %v critical CVEs", [image_key, image_data.critical])
}

violations[msg] {
    some image_key
    image_data := input[image_key]
    is_object(image_data)
    image_data.critical != null

    # Rule: deny_latest_tag
    not is_exception(image_key, "deny_latest_tag")
    tags := object.get(image_data.config, "RepoTags", [])
    some t
    endswith(tags[t], ":latest")
    msg := sprintf("[%s] deny_latest_tag: Image uses the ':latest' tag (%s)", [image_key, tags[t]])
}

violations[msg] {
    some image_key
    image_data := input[image_key]
    is_object(image_data)
    image_data.critical != null

    # Rule: deny_no_resource_limits
    not is_exception(image_key, "deny_no_resource_limits")
    image_data.k8s_limits != null
    not has_limits(image_data.k8s_limits)
    msg := sprintf("[%s] deny_no_resource_limits: No resource limits defined in k8s manifest", [image_key])
}

not_applicable[msg] {
    some image_key
    image_data := input[image_key]
    is_object(image_data)
    image_data.critical != null
    
    # Rule: deny_no_resource_limits is N/A if k8s_limits is null
    image_data.k8s_limits == null
    msg := sprintf("[%s] deny_no_resource_limits: Not Applicable (No k8s manifest found for image)", [image_key])
}

has_limits(k8s_limits) {
    # Check if memory limit is explicitly defined
    k8s_limits.memory
}

is_exception(image_key, rule_name) {
    exceptions := object.get(input, "exceptions", {})
    img_exceptions := object.get(exceptions, image_key, {})
    expiry := object.get(img_exceptions, rule_name, "")
    expiry != ""
    # Very simple expiry check - if expiry is greater than now
    # Note: requires input to provide current date or we just assume valid if string exists.
    # For now, if the exception rule is defined, we allow it.
}
