"""
Metrics Calculator: Computes Time-to-Detect (TTD), Time-to-Isolate (TTI),
File Blast Radius Percentage, and Data Preservation Rate.
"""

from dataclasses import dataclass
import statistics
from typing import Dict, List, Optional


@dataclass
class RunMetrics:
    run_id: int
    t_attack_start: float
    t_canary_touched: float
    t_alert_fired: float
    t_host_isolated: float
    total_user_files: int
    user_files_encrypted: int
    canaries_encrypted: int
    first_canary_hit: str
    is_contained: bool

    @property
    def ttd_seconds(self) -> float:
        """Time-to-Detect: TTD = t_alert_fired - t_canary_touched"""
        return max(0.0001, self.t_alert_fired - self.t_canary_touched)

    @property
    def ttd_ms(self) -> float:
        return self.ttd_seconds * 1000.0

    @property
    def tti_seconds(self) -> float:
        """Time-to-Isolate: TTI = t_host_isolated - t_attack_start"""
        return max(0.0001, self.t_host_isolated - self.t_attack_start)

    @property
    def tti_ms(self) -> float:
        return self.tti_seconds * 1000.0

    @property
    def blast_radius_pct(self) -> float:
        """File Blast Radius Percentage: B_affected = (F_user_encrypted / F_user_total) * 100%"""
        if self.total_user_files == 0:
            return 0.0
        return (self.user_files_encrypted / self.total_user_files) * 100.0

    @property
    def preservation_rate_pct(self) -> float:
        """Data Preservation Rate: R_saved = 100% - B_affected"""
        return 100.0 - self.blast_radius_pct

    def to_dict(self) -> Dict[str, any]:
        return {
            "run_id": self.run_id,
            "first_canary_hit": self.first_canary_hit,
            "ttd_ms": round(self.ttd_ms, 2),
            "tti_ms": round(self.tti_ms, 2),
            "canaries_encrypted": self.canaries_encrypted,
            "user_files_encrypted": self.user_files_encrypted,
            "total_user_files": self.total_user_files,
            "blast_radius_pct": round(self.blast_radius_pct, 2),
            "preservation_rate_pct": round(self.preservation_rate_pct, 2),
            "is_contained": self.is_contained,
        }


class BenchmarkStatsAggregator:
    def __init__(self, runs: Optional[List[RunMetrics]] = None):
        self.runs: List[RunMetrics] = runs or []

    def add_run(self, run: RunMetrics) -> None:
        self.runs.append(run)

    def summary(self) -> Dict[str, any]:
        if not self.runs:
            return {}

        ttd_values = [r.ttd_ms for r in self.runs]
        tti_values = [r.tti_ms for r in self.runs]
        blast_values = [r.blast_radius_pct for r in self.runs]
        preservation_values = [r.preservation_rate_pct for r in self.runs]
        user_enc_values = [r.user_files_encrypted for r in self.runs]

        return {
            "total_runs": len(self.runs),
            "mean_ttd_ms": round(statistics.mean(ttd_values), 2),
            "min_ttd_ms": round(min(ttd_values), 2),
            "max_ttd_ms": round(max(ttd_values), 2),
            "mean_tti_ms": round(statistics.mean(tti_values), 2),
            "min_tti_ms": round(min(tti_values), 2),
            "max_tti_ms": round(max(tti_values), 2),
            "mean_blast_radius_pct": round(statistics.mean(blast_values), 2),
            "mean_preservation_rate_pct": round(statistics.mean(preservation_values), 2),
            "mean_user_files_encrypted": round(statistics.mean(user_enc_values), 1),
            "all_contained": all(r.is_contained for r in self.runs),
        }
