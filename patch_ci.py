import re

with open(".github/workflows/ci.yml", "r") as f:
    ci = f.read()

# Remove old scanner installs and verify
start_idx = ci.find("      - name: Install Scanner Engines")
end_idx = ci.find("      - name: Run Multi-Engine Scan")
ci = ci[:start_idx] + ci[end_idx:]

build_and_scan_steps = """      - name: Build Images
        run: |
          docker build -f Dockerfile.vuln -t flask-app-vulnerable:2.0.0 .
          docker build -f Dockerfile.hardened -t flask-app-hardened:2.0.0 .

      - name: Trivy Scan Vulnerable
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'flask-app-vulnerable:2.0.0'
          format: 'json'
          output: 'trivy-flask-app-vulnerable.json'
        continue-on-error: true

      - name: Trivy Scan Hardened
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'flask-app-hardened:2.0.0'
          format: 'json'
          output: 'trivy-flask-app-hardened.json'
        continue-on-error: true

      - name: Dockle Scan Vulnerable
        uses: goodwithtech/dockle-action@main
        with:
          image: 'flask-app-vulnerable:2.0.0'
          format: 'json'
          exit-code: 0
        continue-on-error: true
      - run: mv dockle-report.json dockle-flask-app-vulnerable.json || true

      - name: Dockle Scan Hardened
        uses: goodwithtech/dockle-action@main
        with:
          image: 'flask-app-hardened:2.0.0'
          format: 'json'
          exit-code: 0
        continue-on-error: true
      - run: mv dockle-report.json dockle-flask-app-hardened.json || true

      - name: Syft Generate Vulnerable
        uses: anchore/sbom-action@v0
        with:
          image: 'flask-app-vulnerable:2.0.0'
          format: 'json'
          output-file: 'syft-flask-app-vulnerable.json'
        continue-on-error: true

      - name: Syft Generate Hardened
        uses: anchore/sbom-action@v0
        with:
          image: 'flask-app-hardened:2.0.0'
          format: 'json'
          output-file: 'syft-flask-app-hardened.json'
        continue-on-error: true

      - name: Grype Scan Vulnerable
        uses: anchore/scan-action@v3
        with:
          image: 'flask-app-vulnerable:2.0.0'
          output-format: 'json'
        continue-on-error: true
      - run: mv results.json grype-flask-app-vulnerable.json || true

      - name: Grype Scan Hardened
        uses: anchore/scan-action@v3
        with:
          image: 'flask-app-hardened:2.0.0'
          output-format: 'json'
        continue-on-error: true
      - run: mv results.json grype-flask-app-hardened.json || true
"""

ci = ci.replace("      - name: Run Multi-Engine Scan", build_and_scan_steps + "\n      - name: Run Multi-Engine Scan")
with open(".github/workflows/ci.yml", "w") as f:
    f.write(ci)

