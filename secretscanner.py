#!/usr/bin/env python3

import argparse
from scanner import Scanner

def main():
    print("""
    ╔══════════════════════════════════════════════════╗
    ║          SecretScanner - Git Leak Detector       ║
    ║                     by 0x127                     ║
    ╚══════════════════════════════════════════════════╝
    """)

    parser = argparse.ArgumentParser(description='Scan for hardcoded secrets in code')
    parser.add_argument('mode', choices=['scan', 'url'], help='Scan local directory or clone repository')
    parser.add_argument('path', help='Directory path or repository URL')
    parser.add_argument('-o', '--output', help='Export results to JSON file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show detailed progress')
    parser.add_argument('--history', action='store_true', help='Include git commit history')

    args = parser.parse_args()

    scan_tool = Scanner(show_progress=args.verbose)

    if args.mode == 'scan':
        scan_tool.check_directory(args.path, check_history=args.history)
    elif args.mode == 'url':
        scan_tool.clone_and_check(args.path, check_history=args.history)

    scan_tool.display_results()

    if args.output:
        scan_tool.save_to_json(args.output)

if __name__ == '__main__':
    main()
