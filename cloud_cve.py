import json
import time
import logging
import os
from pathlib import Path
from typing import Dict, Any, List
import requests
import db

class CloudCVEFetcher:
    def __init__(self, config: Dict[str, Any]):
        cloud_config = config.get("cloud", {})
        self.enabled = cloud_config.get("enabled", False)
        self.sync_interval_hours = cloud_config.get("sync_interval_hours", 6)
        self.source = cloud_config.get("source", "osv")
        self.offline = os.getenv("OFFLINE_MODE", "false").lower() == "true"
        self.cache_file = Path("cve_cache.json")
        
    def _is_cache_stale(self) -> bool:
        if not self.cache_file.exists():
            return True
        mtime = self.cache_file.stat().st_mtime
        age_hours = (time.time() - mtime) / 3600
        return age_hours > self.sync_interval_hours

    def load_cache(self) -> Dict[str, Any]:
        if not self.cache_file.exists():
            return {}
        try:
            with open(self.cache_file, "r") as f:
                return json.load(f)
        except Exception:
            return {}

    def save_cache(self, data: Dict[str, Any]):
        with open(self.cache_file, "w") as f:
            json.dump(data, f)

    def fetch_severity(self, cve_ids: List[str]) -> Dict[str, str]:
        if not self.enabled:
            return {}
            
        cache = self.load_cache()
        stale = self._is_cache_stale()
        
        if self.offline:
            logging.info("OFFLINE_MODE is enabled. Skipping live OSV.dev fetch, using only local cache.")
            return {cve: cache.get(cve, "UNKNOWN") for cve in cve_ids}
        
        results = {}
        to_fetch = []
        
        for cve in cve_ids:
            if cve in cache and not stale:
                results[cve] = cache[cve]
            else:
                to_fetch.append(cve)
                
        if not to_fetch:
            return results
            
        logging.info(f"Fetching cloud CVE data for {len(to_fetch)} items via OSV.dev")
        
        for cve in to_fetch:
            # OSV.dev API
            try:
                # We do this sequentially; for large lists it might be slow, but it's a batch check in audit.py
                resp = requests.get(f"https://api.osv.dev/v1/vulns/{cve}", timeout=2)
                if resp.status_code == 200:
                    data = resp.json()
                    # extract severity if present
                    sev = "UNKNOWN"
                    for severity in data.get("severity", []):
                        if severity.get("type") == "CVSS_V3":
                            sev = severity.get("score", "UNKNOWN")
                            break
                    cache[cve] = sev
                    results[cve] = sev
                else:
                    cache[cve] = "NOT_FOUND"
                    results[cve] = "NOT_FOUND"
            except Exception as e:
                logging.warning(f"Failed to fetch {cve} from OSV.dev: {e}")
                
        if to_fetch:
            self.save_cache(cache)
            
        return results
