import os
import re
import subprocess
import json
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from urllib.parse import urlparse

from patterns import SECRET_PATTERNS, SKIP_EXTENSIONS, SKIP_DIRECTORIES
from utils import calc_entropy, check_if_binary, looks_like_test_data, extract_match_value

class Scanner:
    def __init__(self, show_progress=False):
        self.results = []
        self.files_checked = 0
        self.files_ignored = 0
        self.show_progress = show_progress

    def should_check_file(self, file_path):
        try:
            if not os.path.isfile(file_path):
                return False

            path_components = Path(file_path).parts
            for skip_dir in SKIP_DIRECTORIES:
                if skip_dir in path_components:
                    self.files_ignored += 1
                    return False

            file_ext = Path(file_path).suffix.lower()
            if file_ext in SKIP_EXTENSIONS:
                self.files_ignored += 1
                return False

            size = os.path.getsize(file_path)
            if size == 0:
                self.files_ignored += 1
                return False

            if size > 5 * 1024 * 1024:
                self.files_ignored += 1
                return False

            if check_if_binary(file_path):
                self.files_ignored += 1
                return False

            return True

        except Exception as err:
            if self.show_progress:
                print(f"[ERROR] Checking {file_path}: {err}")
            self.files_ignored += 1
            return False

    def check_text_content(self, text_content, file_path, display_path):
        text_lines = text_content.split('\n')

        for line_number, line_text in enumerate(text_lines, 1):
            if not line_text.strip():
                continue

            for pattern_name, (regex, risk_level) in SECRET_PATTERNS.items():
                try:
                    for regex_match in re.finditer(regex, line_text, re.IGNORECASE):
                        matched_text = extract_match_value(regex_match)

                        if len(matched_text) < 8 or len(matched_text) > 500:
                            continue

                        if looks_like_test_data(matched_text, line_text):
                            continue

                        surrounding_text = line_text.strip()[:150]

                        result_id = f"{display_path}:{line_number}:{pattern_name}:{matched_text}"
                        if not any(r.get('_id') == result_id for r in self.results):
                            result_entry = {
                                'type': pattern_name,
                                'severity': risk_level,
                                'file': display_path,
                                'line': line_number,
                                'secret': matched_text,
                                'entropy': round(calc_entropy(matched_text), 2),
                                'context': surrounding_text,
                                '_id': result_id
                            }
                            self.results.append(result_entry)

                            if self.show_progress:
                                print(f"[FOUND] {risk_level.upper()} - {pattern_name} in {display_path}:{line_number}")

                except Exception as err:
                    if self.show_progress:
                        print(f"[ERROR] Pattern {pattern_name}: {err}")
                    continue

    def check_single_file(self, file_path, base_path=''):
        if not self.should_check_file(file_path):
            return

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                file_contents = f.read()
        except Exception as err:
            if self.show_progress:
                print(f"[ERROR] Reading {file_path}: {err}")
            return

        rel_path = os.path.relpath(file_path, base_path) if base_path else file_path
        self.files_checked += 1

        if self.show_progress and self.files_checked % 25 == 0:
            print(f"[*] Checked {self.files_checked} files...")

        self.check_text_content(file_contents, file_path, rel_path)

    def check_commit_history(self, repo_dir, commit_limit=1000):
        if not os.path.exists(os.path.join(repo_dir, '.git')):
            return

        print(f"\n[*] Checking git history...")

        try:
            git_log = subprocess.run(
                ['git', 'log', '--all', '--pretty=format:%H', '--max-count=' + str(commit_limit)],
                cwd=repo_dir,
                capture_output=True,
                text=True,
                timeout=60
            )

            commit_hashes = git_log.stdout.strip().split('\n')
            print(f"[*] Found {len(commit_hashes)} commits")

            for idx, commit_id in enumerate(commit_hashes):
                if idx % 100 == 0 and idx > 0:
                    print(f"[*] Progress: {idx}/{len(commit_hashes)} commits")

                commit_diff = subprocess.run(
                    ['git', 'show', '--pretty=', '--unified=0', commit_id],
                    cwd=repo_dir,
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                active_file = None
                for diff_line in commit_diff.stdout.split('\n'):
                    if diff_line.startswith('+++'):
                        active_file = diff_line[6:].strip()
                        if active_file.startswith('b/'):
                            active_file = active_file[2:]
                    elif diff_line.startswith('+') and not diff_line.startswith('+++'):
                        added_content = diff_line[1:]
                        if active_file:
                            self.check_text_content(added_content, active_file, f"{active_file} (commit {commit_id[:8]})")

            print(f"[+] Checked {len(commit_hashes)} commits")

        except subprocess.TimeoutExpired:
            print("[!] Git history check timed out")
        except Exception as err:
            if self.show_progress:
                print(f"[!] Git history error: {err}")

    def check_directory(self, dir_path, include_subdirs=True, check_history=False):
        print(f"\n[*] Starting scan: {dir_path}")

        if not os.path.exists(dir_path):
            print(f"[!] Directory not found")
            return

        if include_subdirs:
            for root_dir, subdirs, file_list in os.walk(dir_path):
                subdirs[:] = [d for d in subdirs if d not in SKIP_DIRECTORIES]

                for file_name in file_list:
                    full_path = os.path.join(root_dir, file_name)
                    self.check_single_file(full_path, dir_path)
        else:
            for item_name in os.listdir(dir_path):
                full_path = os.path.join(dir_path, item_name)
                if os.path.isfile(full_path):
                    self.check_single_file(full_path, dir_path)

        print(f"\n[+] Scan complete")
        print(f"[+] Files checked: {self.files_checked}")
        print(f"[+] Files skipped: {self.files_ignored}")

        if check_history:
            self.check_commit_history(dir_path)

    def clone_and_check(self, repo_link, temp_location='/tmp', check_history=False):
        print(f"\n[*] Cloning: {repo_link}")

        repo_id = urlparse(repo_link).path.split('/')[-1].replace('.git', '')
        target_dir = os.path.join(temp_location, f"secretscan_{repo_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")

        try:
            clone_depth = [] if check_history else ['--depth=1']
            clone_result = subprocess.run(
                ['git', 'clone', '--quiet'] + clone_depth + [repo_link, target_dir],
                capture_output=True,
                text=True,
                timeout=180
            )

            if clone_result.returncode != 0:
                print(f"[!] Clone failed: {clone_result.stderr}")
                return None

            print(f"[+] Cloned to: {target_dir}")

        except subprocess.TimeoutExpired:
            print("[!] Clone timeout")
            return None
        except Exception as err:
            print(f"[!] Clone error: {err}")
            return None

        self.check_directory(target_dir, check_history=check_history)
        return target_dir

    def display_results(self):
        print("\n")
        print("=" * 80)
        print("SCAN RESULTS".center(80))
        print("=" * 80)

        if not self.results:
            print("\nNo secrets detected.\n")
            return

        grouped_by_severity = defaultdict(list)
        for finding in self.results:
            grouped_by_severity[finding['severity']].append(finding)

        severity_levels = ['critical', 'high', 'medium', 'low']

        for level in severity_levels:
            if level not in grouped_by_severity:
                continue

            level_results = grouped_by_severity[level]
            print(f"\n{level.upper()} ({len(level_results)} finding{'s' if len(level_results) != 1 else ''})")
            print("-" * 80)

            grouped_by_type = defaultdict(list)
            for finding in level_results:
                grouped_by_type[finding['type']].append(finding)

            for secret_kind in sorted(grouped_by_type.keys()):
                type_results = grouped_by_type[secret_kind]
                print(f"\n  {secret_kind}")
                print(f"  {'─' * 76}")

                for position, finding in enumerate(type_results[:5], 1):
                    print(f"  [{position}] File: {finding['file']}")
                    print(f"      Line: {finding['line']}")
                    print(f"      Secret: {finding['secret']}")
                    print(f"      Entropy: {finding['entropy']}")
                    if len(finding['context']) > 100:
                        print(f"      Context: {finding['context'][:100]}...")
                    else:
                        print(f"      Context: {finding['context']}")
                    if position < len(type_results[:5]):
                        print()

                if len(type_results) > 5:
                    print(f"\n  ... and {len(type_results) - 5} more occurrence(s)")

        print("\n" + "=" * 80)
        crit_count = len(grouped_by_severity.get('critical', []))
        high_count = len(grouped_by_severity.get('high', []))
        med_count = len(grouped_by_severity.get('medium', []))
        low_count = len(grouped_by_severity.get('low', []))

        print(f"SUMMARY: {len(self.results)} total secrets found".center(80))
        print(f"Critical: {crit_count}  |  High: {high_count}  |  Medium: {med_count}  |  Low: {low_count}".center(80))
        print(f"Scanned: {self.files_checked} files  |  Skipped: {self.files_ignored} files".center(80))
        print("=" * 80)
        print()

    def save_to_json(self, output_path):
        report_data = {
            'scan_time': datetime.now().isoformat(),
            'files_scanned': self.files_checked,
            'files_skipped': self.files_ignored,
            'total_findings': len(self.results),
            'findings': [
                {k: v for k, v in finding.items() if k != '_id'}
                for finding in self.results
            ]
        }

        with open(output_path, 'w') as output_file:
            json.dump(report_data, output_file, indent=2)
        print(f"\n[+] Report saved: {output_path}")
