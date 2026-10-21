"""
Sandbox Builder: Creates simulated enterprise directory structures with
canary tripwire files and realistic dummy user files.
"""

from dataclasses import dataclass
import json
import os
from pathlib import Path
import random
import shutil
from typing import Dict, List, Optional


@dataclass
class CanaryItem:
    filename: str
    file_type: str
    magic_header: bytes
    content_prefix: str
    size_bytes: int


class SandboxBuilder:
    SUBDIRECTORIES = [
        "Finance_Records",
        "Executive_Documents",
        "Desktop_Workspace",
        "Public_Shared",
    ]

    USER_FILE_PREFIXES = [
        "Account_Statement",
        "Budget_Forecast",
        "Client_Contract",
        "Customer_Ledger",
        "Employee_Directory",
        "Invoice_Summary",
        "Operations_Manual",
        "Project_Specification",
        "Quarterly_Report",
        "Vendor_Agreement",
    ]

    USER_EXTENSIONS = [".pdf", ".docx", ".xlsx", ".csv", ".txt", ".pptx"]

    def __init__(self, base_dir: Path, config: Optional[dict] = None):
        self.base_dir = Path(base_dir).resolve()
        self.config = config or {}
        exp_settings = self.config.get("experiment_settings", {})
        self.total_user_files = exp_settings.get("total_dummy_user_files", 500)
        self.canary_defs = self._init_canary_defs()

    def _init_canary_defs(self) -> List[CanaryItem]:
        canaries_cfg = self.config.get("canary_files", [])
        if not canaries_cfg:
            # Fallback default canonical canaries
            return [
                CanaryItem(
                    filename="!000_CONFIDENTIAL_Payroll_2026.xlsx",
                    file_type="spreadsheet_honeytoken",
                    magic_header=b"PK\x03\x04",
                    content_prefix="[CONFIDENTIAL SALARY MATRIX 2026]\n",
                    size_bytes=46080,
                ),
                CanaryItem(
                    filename="#000_AWS_Production_Root_Keys.txt",
                    file_type="credential_honeytoken",
                    magic_header=b"",
                    content_prefix="AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
                    size_bytes=15360,
                ),
                CanaryItem(
                    filename="$000_Executive_M&A_Targets.docx",
                    file_type="document_honeytoken",
                    magic_header=b"PK\x03\x04",
                    content_prefix="[RESTRICTED MERGERS & ACQUISITIONS BRIEF]\n",
                    size_bytes=66560,
                ),
                CanaryItem(
                    filename="_000_Backup_Recovery_Seeds.pdf",
                    file_type="pdf_honeytoken",
                    magic_header=b"%PDF-1.7\n",
                    content_prefix="[RECOVERY VAULT CIPHER SEED RECORDS]\n",
                    size_bytes=87040,
                ),
            ]

        items = []
        for c in canaries_cfg:
            magic = c.get("magic_header", "")
            if isinstance(magic, str):
                magic_bytes = magic.encode().decode("unicode_escape").encode("latin1")
            else:
                magic_bytes = bytes(magic)
            prefix = c.get("content_prefix", "")
            items.append(
                CanaryItem(
                    filename=c["filename"],
                    file_type=c.get("type", "honeytoken"),
                    magic_header=magic_bytes,
                    content_prefix=prefix,
                    size_bytes=32768,
                )
            )
        return items

    def clean(self) -> None:
        """Removes the entire sandbox directory tree."""
        if self.base_dir.exists():
            shutil.rmtree(self.base_dir, ignore_errors=True)

    def build(self) -> Dict[str, any]:
        """
        Builds the complete sandbox environment:
        - 4 target subdirectories
        - 16 planted canary files (4 per directory)
        - 500 dummy user files distributed evenly
        Returns manifest metadata.
        """
        self.clean()
        self.base_dir.mkdir(parents=True, exist_ok=True)

        canary_paths: List[str] = []
        user_file_paths: List[str] = []
        folder_paths: List[Path] = []

        # Create subdirectories
        for sub in self.SUBDIRECTORIES:
            fpath = self.base_dir / sub
            fpath.mkdir(parents=True, exist_ok=True)
            folder_paths.append(fpath)

        # Plant Canaries (4 per folder = 16 total)
        for folder in folder_paths:
            for item in self.canary_defs:
                cpath = folder / item.filename
                with open(cpath, "wb") as f:
                    if item.magic_header:
                        f.write(item.magic_header)
                    if item.content_prefix:
                        f.write(item.content_prefix.encode("utf-8"))
                    # Fill dummy payload
                    current_len = f.tell()
                    padding_len = max(512, item.size_bytes - current_len)
                    f.write(os.urandom(padding_len))
                canary_paths.append(str(cpath))

        # Distribute user files evenly across folders
        files_per_folder = self.total_user_files // len(folder_paths)
        file_counter = 1

        for idx, folder in enumerate(folder_paths):
            # Account for rounding on the last folder
            count = (
                files_per_folder
                if idx < len(folder_paths) - 1
                else (self.total_user_files - (files_per_folder * (len(folder_paths) - 1)))
            )

            for _ in range(count):
                prefix = random.choice(self.USER_FILE_PREFIXES)
                ext = random.choice(self.USER_EXTENSIONS)
                fname = f"{prefix}_{file_counter:04d}{ext}"
                upath = folder / fname

                with open(upath, "wb") as f:
                    # Provide realistic simulated headers
                    if ext in [".xlsx", ".docx", ".pptx"]:
                        f.write(b"PK\x03\x04")
                    elif ext == ".pdf":
                        f.write(b"%PDF-1.7\n")
                    f.write(
                        f"Standard Enterprise Document Payload #{file_counter}\n".encode("utf-8")
                    )
                    f.write(os.urandom(random.randint(4096, 32768)))

                user_file_paths.append(str(upath))
                file_counter += 1

        manifest = {
            "sandbox_root": str(self.base_dir),
            "total_canaries": len(canary_paths),
            "total_user_files": len(user_file_paths),
            "total_files": len(canary_paths) + len(user_file_paths),
            "directories": [str(p) for p in folder_paths],
            "canary_files": canary_paths,
            "user_files": user_file_paths,
        }

        # Save manifest
        manifest_path = self.base_dir / "sandbox_manifest.json"
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        return manifest


if __name__ == "__main__":
    builder = SandboxBuilder(Path("./sandbox_drive"))
    meta = builder.build()
    print(
        f"Built sandbox: {meta['total_canaries']} canaries, {meta['total_user_files']} user files."
    )
