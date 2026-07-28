import os, json
for tool in ['trivy', 'dockle', 'syft', 'grype']:
    for img in ['flask-app-vulnerable', 'flask-app-hardened']:
        with open(f"{tool}-{img}.json", 'w') as f:
            if tool == 'trivy':
                f.write('{}')
            else:
                f.write('{}')
