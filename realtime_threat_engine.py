#!/usr/bin/env python3
"""Production-oriented real-time Docker threat + CVE monitoring engine.

Features:
- Monitors all running containers continuously.
- Ensemble runtime anomaly detection (rules + z-score + EWMA + pretrained AI model).
- Real-time CVE enrichment per running image (Trivy JSON), including suggested fixes.
- Alert generation for high-risk runtime behavior and critical/high CVEs.
- On-demand report generation (JSON/TXT).
"""

from __future__ import annotations

import concurrent.futures
import logging

__version__ = "2.0.0"

from logger import setup_logger
logger = setup_logger("realtime_engine")

import json
import os
import shutil
import statistics
import subprocess
import time
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple

from ai_security_model import RuleBasedAnomalyScorer, MLAnomalyDetector

try:
    import yaml
except ImportError:
    yaml = None

try:
    import docker
except ImportError:
    docker = None

try:
    import requests
except ImportError:
    requests = None

OUTPUT_DIR = Path("runtime")
OUTPUT_FILE = OUTPUT_DIR / "runtime_threats_latest.json"
REPORTS_DIR = Path("reports")


@dataclass
class ContainerSignal:
    container_id: str
    name: str
    image: str
    status: str
    cpu_percent: float
    memory_percent: float
    network_rx_mb: float
    network_tx_mb: float
    pids: int
    restart_count: int
    ai_anomaly_score: float
    score: int
    risk_level: str
    reasons: List[str]
    detectors_triggered: List[str]
    cve_critical: int
    cve_high: int
    top_cves: List[Dict[str, str]]
    recommended_fixes: List[str]
    timestamp: str


class VulnerabilityScanner:
    """Trivy-based vulnerability scanner with per-image caching."""

    def __init__(self, enabled: bool = True, cache_ttl_seconds: int = 900):
        self.enabled = enabled
        self.cache_ttl_seconds = cache_ttl_seconds
        self.cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}

    @staticmethod
    def _tool_exists() -> bool:
        return shutil.which("trivy") is not None

    def _run_trivy(self, image: str) -> Dict[str, Any]:
        if not self.enabled or not self._tool_exists():
            return {"critical": 0, "high": 0, "top_cves": [], "recommended_fixes": [], "scanner": "unavailable"}

        proc = subprocess.run(
            ["trivy", "image", "--format", "json", "--quiet", image],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return {"critical": 0, "high": 0, "top_cves": [], "recommended_fixes": [], "scanner": "error"}

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return {"critical": 0, "high": 0, "top_cves": [], "recommended_fixes": [], "scanner": "parse_error"}

        cves: List[Dict[str, str]] = []
        critical = high = 0
        fixes = set()

        for result in data.get("Results", []) or []:
            for vuln in result.get("Vulnerabilities", []) or []:
                sev = (vuln.get("Severity") or "").upper()
                if sev == "CRITICAL":
                    critical += 1
                elif sev == "HIGH":
                    high += 1

                fixed = vuln.get("FixedVersion") or ""
                pkg = vuln.get("PkgName") or "unknown"
                installed = vuln.get("InstalledVersion") or "unknown"
                if fixed:
                    fixes.add(f"Update {pkg} from {installed} to {fixed}")

                cves.append(
                    {
                        "cve": vuln.get("VulnerabilityID", "N/A"),
                        "severity": sev or "UNKNOWN",
                        "package": pkg,
                        "installed_version": installed,
                        "fixed_version": fixed or "N/A",
                        "title": vuln.get("Title", "")[:120],
                    }
                )

        cves.sort(key=lambda c: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(c["severity"], 9))
        return {
            "critical": critical,
            "high": high,
            "top_cves": cves[:8],
            "recommended_fixes": sorted(list(fixes))[:10],
            "scanner": "trivy",
        }

    def scan_image(self, image: str) -> Dict[str, Any]:
        now = time.time()
        cached = self.cache.get(image)
        if cached and (now - cached[0] < self.cache_ttl_seconds):
            return cached[1]

        result = self._run_trivy(image)
        self.cache[image] = (now, result)
        return result


class ThreatScorer:
    """Ensemble detector for runtime anomalies."""

    def __init__(self, window_size: int = 16):
        self.window_size = window_size
        self.history: Dict[str, Dict[str, Deque[float]]] = defaultdict(
            lambda: {
                "cpu": deque(maxlen=self.window_size),
                "memory": deque(maxlen=self.window_size),
                "network": deque(maxlen=self.window_size),
                "pids": deque(maxlen=self.window_size),
            }
        )
        self.ewma: Dict[str, Dict[str, float]] = defaultdict(dict)
        self.rule_model = RuleBasedAnomalyScorer()
        self.ml_model = MLAnomalyDetector()

    @staticmethod
    def _risk_bucket(score: int) -> str:
        if score >= 78:
            return "critical"
        if score >= 55:
            return "high"
        if score >= 30:
            return "medium"
        return "low"

    @staticmethod
    def _zscore(value: float, samples: Deque[float]) -> float:
        if len(samples) < 6:
            return 0.0
        mean = statistics.mean(samples)
        std = statistics.pstdev(samples)
        if std == 0:
            return 0.0
        return (value - mean) / std

    def _ewma_spike(self, cid: str, key: str, value: float, alpha: float = 0.3) -> float:
        prev = self.ewma[cid].get(key, value)
        smooth = alpha * value + (1 - alpha) * prev
        self.ewma[cid][key] = smooth
        return 0.0 if smooth == 0 else (value - smooth) / max(smooth, 1e-6)

    def score(self, metrics: Dict[str, Any], cve_critical: int, cve_high: int) -> Dict[str, Any]:
        cid = metrics["container_id"]
        h = self.history[cid]

        cpu = float(metrics["cpu_percent"])
        mem = float(metrics["memory_percent"])
        net = float(metrics["network_rx_mb"] + metrics["network_tx_mb"])
        pids = float(metrics["pids"])
        restart_count = float(metrics["restart_count"])

        reasons: List[str] = []
        detectors: List[str] = []
        score = 0

        cpu_z = self._zscore(cpu, h["cpu"])
        mem_z = self._zscore(mem, h["memory"])
        net_z = self._zscore(net, h["network"])
        pid_z = self._zscore(pids, h["pids"])

        if cpu > 90:
            score += 20
            reasons.append("CPU > 90%")
            detectors.append("rule")
        if mem > 85:
            score += 18
            reasons.append("Memory > 85%")
            detectors.append("rule")
        if pids > 250:
            score += 15
            reasons.append("PIDs > 250")
            detectors.append("rule")
        if net > 300:
            score += 15
            reasons.append("Network throughput spike (>300MB)")
            detectors.append("rule")

        if cpu_z > 2.5:
            score += 12
            reasons.append(f"CPU z-score anomaly ({cpu_z:.2f})")
            detectors.append("zscore")
        if mem_z > 2.5:
            score += 10
            reasons.append(f"Memory z-score anomaly ({mem_z:.2f})")
            detectors.append("zscore")
        if net_z > 3.0:
            score += 12
            reasons.append(f"Network z-score anomaly ({net_z:.2f})")
            detectors.append("zscore")
        if pid_z > 3.0:
            score += 12
            reasons.append(f"PID z-score anomaly ({pid_z:.2f})")
            detectors.append("zscore")

        cpu_spike = self._ewma_spike(cid, "cpu", cpu)
        mem_spike = self._ewma_spike(cid, "memory", mem)
        net_spike = self._ewma_spike(cid, "network", net)
        if cpu_spike > 0.8 or mem_spike > 0.8 or net_spike > 1.2:
            score += 10
            reasons.append("EWMA sudden-behavior shift detected")
            detectors.append("ewma")

        features = {
            "cpu": cpu,
            "memory": mem,
            "network_total": net,
            "pids": pids,
            "restart_count": restart_count,
            "cpu_z": cpu_z,
            "memory_z": mem_z,
            "network_z": net_z,
            "pid_z": pid_z,
        }
        rule_score = self.rule_model.score(features)
        ml_score = self.ml_model.score(features)
        
        # Ensemble approach: average the rule-based heuristic score with the true ML anomaly score
        ai_score = (rule_score + ml_score) / 2

        if ai_score > 75:
            score += 22
            reasons.append(f"AI model high anomaly probability ({ai_score:.1f})")
            detectors.append("ai_model")
        elif ai_score > 55:
            score += 10
            reasons.append(f"AI model moderate anomaly probability ({ai_score:.1f})")
            detectors.append("ai_model")

        if cve_critical > 0:
            score += min(25, cve_critical * 5)
            reasons.append(f"Critical CVEs present: {cve_critical}")
            detectors.append("vuln_cve")
        if cve_high > 0:
            score += min(15, cve_high * 2)
            reasons.append(f"High CVEs present: {cve_high}")
            detectors.append("vuln_cve")
        if restart_count >= 3:
            score += 8
            reasons.append("Restart churn (>=3)")
            detectors.append("rule")

        for key, value in (("cpu", cpu), ("memory", mem), ("network", net), ("pids", pids)):
            h[key].append(value)

        score = min(int(round(score)), 100)
        if not reasons:
            reasons = ["No significant anomalies detected"]
            
        ai_explanation = ""
        if score >= 75: # Alert threshold roughly
            exp_parts = []
            if cpu_z > 2.0:
                exp_parts.append(f"abnormal CPU usage {cpu_z:.1f} standard deviations above baseline")
            elif cpu > 80:
                exp_parts.append(f"high CPU usage of {cpu:.1f}%")
            if net_z > 2.0:
                exp_parts.append(f"elevated network activity {net_z:.1f} standard deviations above baseline")
            elif net > 100:
                exp_parts.append(f"elevated network activity ({net:.1f} MB)")
            if mem_z > 2.0:
                exp_parts.append(f"abnormal memory usage {mem_z:.1f} standard deviations above baseline")
            if pid_z > 2.0:
                exp_parts.append(f"abnormal process count {pid_z:.1f} standard deviations above baseline")
            if cve_critical > 0:
                exp_parts.append(f"the presence of {cve_critical} critical CVEs")
                
            if exp_parts:
                ai_explanation = "The combination of " + " and ".join(exp_parts[:2])
                if len(exp_parts) > 2:
                    ai_explanation += " along with other anomalies"
                ai_explanation += " suggests potential resource abuse, exploitation, or anomalous behavior."
            else:
                ai_explanation = "Multiple heuristics triggered indicating anomalous behavior, though no single metric deviated extremely."

        return {
            "score": score,
            "risk_level": self._risk_bucket(score),
            "reasons": reasons,
            "detectors_triggered": sorted(set(detectors)),
            "ai_anomaly_score": ai_score,
            "ai_explanation": ai_explanation,
        }


class RuntimeThreatEngine:
    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = Path(config_path)
        self.config = self._load_config()
        rt = self.config.get("runtime_monitoring", {})
        cloud = self.config.get("cloud", {})

        self.interval_seconds = int(rt.get("poll_interval_seconds", 20))
        self.enabled = bool(rt.get("enabled", True))
        self.cloud_enabled = bool(cloud.get("enabled", False))
        self.cloud_endpoint = cloud.get("endpoint", "")
        self.cloud_api_key = os.getenv(cloud.get("api_key_env", "CVE_CLOUD_API_KEY"), "")

        vuln_cfg = self.config.get("vulnerability_monitoring", {})
        self.vuln_scanner = VulnerabilityScanner(
            enabled=bool(vuln_cfg.get("enabled", True)),
            cache_ttl_seconds=int(vuln_cfg.get("image_scan_cache_ttl_seconds", 900)),
        )

        self.scorer = ThreatScorer(window_size=int(rt.get("ai_window_size", 16)))
        
        from alerting import AlertManager
        self.alert_manager = AlertManager(self.config)

        if docker is None:
            raise RuntimeError("docker package is not installed. Install with: pip install docker")
            
        self.hosts = rt.get("hosts", ["unix://var/run/docker.sock"])
        self.clients = []
        for host in self.hosts:
            try:
                if host == "unix://var/run/docker.sock" or host == "local":
                    self.clients.append(docker.from_env())
                else:
                    self.clients.append(docker.DockerClient(base_url=host))
            except Exception as e:
                logging.error(f"Failed to connect to docker host {host}: {e}")

    def _load_config(self) -> Dict[str, Any]:
        if not self.config_path.exists() or yaml is None:
            return {}
        with open(self.config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    @staticmethod
    def _safe_num(value: Any) -> float:
        try:
            return max(float(value), 0.0)
        except (TypeError, ValueError):
            return 0.0

    @staticmethod
    def _calc_cpu_percent(stats: Dict[str, Any]) -> float:
        cpu_stats = stats.get("cpu_stats", {})
        precpu = stats.get("precpu_stats", {})
        cpu_delta = cpu_stats.get("cpu_usage", {}).get("total_usage", 0) - precpu.get("cpu_usage", {}).get("total_usage", 0)
        sys_delta = cpu_stats.get("system_cpu_usage", 0) - precpu.get("system_cpu_usage", 0)
        cpus = cpu_stats.get("online_cpus") or len(cpu_stats.get("cpu_usage", {}).get("percpu_usage", []) or [1])
        if sys_delta > 0 and cpu_delta > 0:
            return (cpu_delta / sys_delta) * cpus * 100.0
        return 0.0

    @staticmethod
    def _calc_memory_percent(stats: Dict[str, Any]) -> float:
        mem = stats.get("memory_stats", {})
        usage = float(mem.get("usage", 0))
        limit = float(mem.get("limit", 0))
        return (usage / limit) * 100.0 if limit > 0 else 0.0

    @staticmethod
    def _calc_network_mb(stats: Dict[str, Any]) -> Dict[str, float]:
        networks = stats.get("networks", {}) or {}
        rx = sum(v.get("rx_bytes", 0) for v in networks.values()) / (1024 * 1024)
        tx = sum(v.get("tx_bytes", 0) for v in networks.values()) / (1024 * 1024)
        return {"rx": rx, "tx": tx}

    def collect_signals(self) -> List[ContainerSignal]:
        findings: List[ContainerSignal] = []
        containers = []
        for client in self.clients:
            try:
                containers.extend(client.containers.list())
            except Exception as e:
                logging.error(f"Failed to list containers: {e}")

        def process_container(container) -> ContainerSignal:
            stats = container.stats(stream=False)
            net = self._calc_network_mb(stats)
            image_ref = container.image.tags[0] if container.image.tags else container.image.short_id
            vuln = self.vuln_scanner.scan_image(image_ref)
            metrics = {
                "container_id": container.id[:12],
                "name": container.name,
                "image": image_ref,
                "status": container.status,
                "cpu_percent": self._safe_num(self._calc_cpu_percent(stats)),
                "memory_percent": self._safe_num(self._calc_memory_percent(stats)),
                "network_rx_mb": self._safe_num(net["rx"]),
                "network_tx_mb": self._safe_num(net["tx"]),
                "pids": int((stats.get("pids_stats") or {}).get("current", 0)),
                "restart_count": int((container.attrs or {}).get("RestartCount", 0)),
            }
            try:
                import db
                is_protected = db.is_container_protected(container.id[:12])
            except Exception:
                is_protected = False

            if is_protected:
                metrics["is_protected"] = True
                
            scored = self.scorer.score(metrics, vuln.get("critical", 0), vuln.get("high", 0))
            
            threshold = self.alert_manager.threshold - 20 if is_protected else self.alert_manager.threshold
            
            self.alert_manager.trigger_alert(
                scored["score"],
                f"{'[PROTECTED] ' if is_protected else ''}High threat score for container {container.name} (image: {image_ref})",
                scored,
                threshold_override=threshold
            )
            
            return ContainerSignal(
                **metrics,
                ai_anomaly_score=scored["ai_anomaly_score"],
                score=scored["score"],
                risk_level=scored["risk_level"],
                reasons=scored["reasons"],
                detectors_triggered=scored["detectors_triggered"],
                cve_critical=int(vuln.get("critical", 0)),
                cve_high=int(vuln.get("high", 0)),
                top_cves=vuln.get("top_cves", []),
                recommended_fixes=vuln.get("recommended_fixes", []),
                timestamp=datetime.now(timezone.utc).isoformat(),
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(10, len(containers) or 1)) as executor:
            future_to_c = {executor.submit(process_container, c): c for c in containers}
            for future in concurrent.futures.as_completed(future_to_c):
                c = future_to_c[future]
                try:
                    findings.append(future.result(timeout=10.0))
                except concurrent.futures.TimeoutError:
                    logging.exception(f"Timeout analyzing container {c.name}")
                except Exception:
                    logging.exception(f"Failed analyzing container {c.name}")

        return findings

    def _build_alerts(self, signals: List[ContainerSignal]) -> List[Dict[str, Any]]:
        alerts: List[Dict[str, Any]] = []
        for s in signals:
            if s.risk_level in {"critical", "high"} or s.cve_critical > 0:
                alerts.append(
                    {
                        "container": s.name,
                        "risk_level": s.risk_level,
                        "runtime_score": s.score,
                        "ai_anomaly_score": s.ai_anomaly_score,
                        "cve_critical": s.cve_critical,
                        "cve_high": s.cve_high,
                        "top_cve": s.top_cves[0] if s.top_cves else None,
                        "recommended_fix": s.recommended_fixes[0] if s.recommended_fixes else None,
                        "timestamp": s.timestamp,
                    }
                )
        return alerts

    def export_local(self, signals: List[ContainerSignal]) -> Dict[str, Any]:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

        risk = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        total_critical = total_high = 0
        for s in signals:
            risk[s.risk_level] += 1
            total_critical += s.cve_critical
            total_high += s.cve_high

        payload = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "containers_monitored": len(signals),
                "critical_alerts": risk["critical"],
                "high_alerts": risk["high"],
                "medium_alerts": risk["medium"],
                "low_alerts": risk["low"],
                "mean_ai_anomaly_score": round(sum(s.ai_anomaly_score for s in signals) / len(signals), 2) if signals else 0,
                "total_cve_critical": total_critical,
                "total_cve_high": total_high,
                "containers_with_vulns": sum(1 for s in signals if s.cve_critical > 0 or s.cve_high > 0),
            },
            "alerts": self._build_alerts(signals),
            "findings": [asdict(s) for s in signals],
        }

        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

        try:
            import db
            for alert in payload.get("alerts", []):
                db.save_runtime_event(alert)
        except Exception as e:
            logging.error(f"Failed to save runtime events to DB: {e}")

        return payload

    def generate_report(self, payload: Dict[str, Any], fmt: str = "json") -> Path:
        REPORTS_DIR.mkdir(exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")

        if fmt == "txt":
            out = REPORTS_DIR / f"runtime_security_report_{ts}.txt"
            s = payload.get("summary", {})
            lines = [
                "Runtime Security Report",
                "=" * 72,
                f"Generated: {payload.get('generated_at')}",
                f"Containers monitored: {s.get('containers_monitored', 0)}",
                f"Runtime alerts (critical/high): {s.get('critical_alerts', 0)}/{s.get('high_alerts', 0)}",
                f"CVEs critical/high: {s.get('total_cve_critical', 0)}/{s.get('total_cve_high', 0)}",
                "",
                "Alerts:",
            ]
            for a in payload.get("alerts", []):
                lines.append(
                    f"- {a['container']} | risk={a['risk_level']} score={a['runtime_score']} ai={a['ai_anomaly_score']} "
                    f"CVE(C/H)={a['cve_critical']}/{a['cve_high']} fix={a.get('recommended_fix') or 'n/a'}"
                )
            out.write_text("\n".join(lines), encoding="utf-8")
            return out

        out = REPORTS_DIR / f"runtime_security_report_{ts}.json"
        out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return out

    def checkin_cloud(self, payload: Dict[str, Any]) -> Optional[int]:
        if not self.cloud_enabled or requests is None:
            return None
        if not self.cloud_endpoint or "localhost" in self.cloud_endpoint or "example" + ".com" in self.cloud_endpoint:
            logging.warning(f"Invalid cloud endpoint configured: {self.cloud_endpoint}. Skipping.")
            return None
        headers = {"Content-Type": "application/json"}
        if self.cloud_api_key:
            headers["Authorization"] = f"Bearer {self.cloud_api_key}"
        try:
            return requests.post(self.cloud_endpoint, json=payload, headers=headers, timeout=15).status_code
        except Exception:
            return None

    def run_once(self) -> Dict[str, Any]:
        payload = self.export_local(self.collect_signals())
        self.checkin_cloud(payload)
        return payload

    def run_forever(self):
        if not self.enabled:
            logging.info("runtime monitoring disabled")
            return
        logger = logging.getLogger("realtime_engine")
        logger.info(f"Runtime Threat Engine running every {self.interval_seconds}s", extra={"extra_fields": {"interval": self.interval_seconds}})
        while True:
            try:
                payload = self.run_once()
                s = payload["summary"]
                logger.info(
                    f"cycle complete: monitored={s['containers_monitored']} critical={s['critical_alerts']} "
                    f"high={s['high_alerts']} cveCritical={s['total_cve_critical']} ai_mean={s['mean_ai_anomaly_score']}"
                )
            except KeyboardInterrupt:
                logging.info("stopped")
                break
            except docker.errors.APIError as exc:
                logging.exception(f"Docker API error during cycle: {exc}")
            except docker.errors.DockerException as exc:
                logging.exception(f"Docker exception during cycle: {exc}")
            except Exception as exc:
                logging.exception(f"cycle failed: {exc}")
            time.sleep(self.interval_seconds)


if __name__ == "__main__":
    engine = RuntimeThreatEngine("config.yaml")
    mode = os.getenv("RUNTIME_MONITOR_MODE", "forever").lower()
    if mode == "once":
        payload = engine.run_once()
        report_fmt = os.getenv("RUNTIME_REPORT_FORMAT", "")
        if report_fmt in {"json", "txt"}:
            report_path = engine.generate_report(payload, report_fmt)
            logging.info(f"report generated: {report_path}")
    else:
        engine.run_forever()
