#!/usr/bin/env python3

import subprocess
import json
import sys
import os
import pwd
import grp
import getpass
import logging
import platform
import textwrap
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum

try:
    from tabulate import tabulate
    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


class Color:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'


@dataclass
class UserInfo:
    name: str
    uid: int
    gid: int
    home: str
    groups: List[str]
    linger: Optional[bool] = None


@dataclass
class SystemdDir:
    name: str
    path: Path
    exists: bool
    is_directory: bool
    unit_count: int = 0
    accessible: bool = True


@dataclass
class SystemdUnit:
    name: str
    state: str
    load: str = "unknown"
    active: str = "unknown"
    sub: str = "unknown"
    description: str = ""


@dataclass
class SystemdTimer:
    name: str
    next_activation: Optional[str] = None
    time_left: Optional[str] = None
    last_activation: Optional[str] = None


class SystemdUserChecker:
    def __init__(self, verbose=False, color=True):
        self.verbose = verbose
        self.use_color = color and sys.stdout.isatty()
        self.logger = self._setup_logger()
        self.user_info = None
        self.directories = []
        self.services = []
        self.sockets = []
        self.timers = []
        self.manager_status = {}
        self.summary = {}
        self._validate_environment()
    
    def _setup_logger(self):
        logger = logging.getLogger(__name__)
        if not logger.handlers:
            handler = logging.StreamHandler(sys.stderr)
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.DEBUG if self.verbose else logging.INFO)
        return logger
    
    def _validate_environment(self):
        if platform.system() != 'Linux':
            self._error("This tool only works on Linux systems")
            sys.exit(1)
        
        try:
            result = subprocess.run(
                ['systemctl', '--version'],
                capture_output=True,
                text=True,
                check=False
            )
            if result.returncode != 0:
                self._error("Systemd not found or not accessible")
                sys.exit(1)
        except FileNotFoundError:
            self._error("systemctl command not found")
            sys.exit(1)
    
    def _colorize(self, text, color):
        if self.use_color:
            return f"{color}{text}{Color.RESET}"
        return text
    
    def _error(self, message):
        print(f"{self._colorize('Error:', Color.RED)} {message}", file=sys.stderr)
        self.logger.error(message)
    
    def _warning(self, message):
        print(f"{self._colorize('Warning:', Color.YELLOW)} {message}", file=sys.stderr)
        self.logger.warning(message)
    
    def _run_command(self, cmd_args, capture=True):
        try:
            self.logger.debug(f"Running command: {' '.join(cmd_args)}")
            result = subprocess.run(
                cmd_args,
                capture_output=capture,
                text=True,
                check=False,
                timeout=30
            )
            return result.stdout.strip(), result.returncode
        except subprocess.TimeoutExpired:
            self._warning(f"Command timed out: {' '.join(cmd_args)}")
            return "Command timed out", 124
        except Exception as e:
            self.logger.error(f"Command failed: {e}")
            return str(e), 1
    
    def _run_user_command(self, cmd_args):
        if os.getuid() == self.user_info.uid:
            return self._run_command(cmd_args)
        
        user_cmd = ['systemd-run', '--user', '--wait', '--pipe'] + cmd_args
        return self._run_command(user_cmd)
    
    def get_current_user(self):
        try:
            username = getpass.getuser()
            pw_entry = pwd.getpwnam(username)
            
            groups = []
            try:
                for group in grp.getgrall():
                    if username in group.gr_mem:
                        groups.append(group.gr_name)
            except Exception as e:
                self._warning(f"Could not get group memberships: {e}")
            
            self.user_info = UserInfo(
                name=username,
                uid=pw_entry.pw_uid,
                gid=pw_entry.pw_gid,
                home=pw_entry.pw_dir,
                groups=groups
            )
            
            self._display_user_info()
            return self.user_info
            
        except Exception as e:
            self._error(f"Failed to get user info: {e}")
            sys.exit(1)
    
    def _display_user_info(self):
        if not self.user_info:
            return
        
        data = [
            ["Username", self.user_info.name],
            ["User ID", str(self.user_info.uid)],
            ["Group ID", str(self.user_info.gid)],
            ["Home Directory", self.user_info.home],
            ["Groups", ", ".join(self.user_info.groups[:10]) + 
             ("..." if len(self.user_info.groups) > 10 else "")]
        ]
        
        self._display_table("CURRENT USER INFORMATION", ["Property", "Value"], data)
    
    def check_user_directories(self):
        if not self.user_info:
            self.get_current_user()
        
        directories = [
            ("User Config", Path(self.user_info.home) / ".config/systemd/user"),
            ("User Runtime", Path(f"/run/user/{self.user_info.uid}")),
            ("User Local", Path(self.user_info.home) / ".local/share/systemd/user"),
            ("System User", Path(f"/usr/lib/systemd/user")),
            ("System Local", Path(f"/usr/local/lib/systemd/user"))
        ]
        
        dir_objects = []
        display_data = []
        
        for name, path in directories:
            exists = path.exists()
            is_dir = path.is_dir() if exists else False
            unit_count = 0
            accessible = True
            
            if exists and is_dir:
                try:
                    unit_extensions = ['.service', '.socket', '.timer', '.target', '.mount', '.automount']
                    for ext in unit_extensions:
                        unit_count += len(list(path.glob(f"*{ext}")))
                except PermissionError:
                    accessible = False
                    unit_count = -1
                except Exception as e:
                    self._warning(f"Could not scan {path}: {e}")
                    accessible = False
            
            dir_obj = SystemdDir(
                name=name,
                path=path,
                exists=exists,
                is_directory=is_dir,
                unit_count=unit_count,
                accessible=accessible
            )
            dir_objects.append(dir_obj)
            
            if not exists:
                status = self._colorize("Missing", Color.RED)
            elif not accessible:
                status = self._colorize("Access Denied", Color.YELLOW)
            elif unit_count > 0:
                status = self._colorize(f"Present ({unit_count} units)", Color.GREEN)
            else:
                status = self._colorize("Present (empty)", Color.BLUE)
            
            display_data.append([name, str(path), status])
        
        self.directories = dir_objects
        self._display_table("USER SYSTEMD DIRECTORIES", ["Directory", "Path", "Status"], display_data)
        
        return dir_objects
    
    def check_systemd_manager(self):
        output, code = self._run_user_command(['systemctl', '--user', '--no-pager', 'status'])
        
        status_data = {}
        display_data = []
        
        if code == 0:
            lines = output.split('\n')
            for line in lines:
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    status_data[key] = value
                    
                    if key == 'State' and 'running' in value.lower():
                        display_value = self._colorize(value, Color.GREEN)
                    elif key == 'State':
                        display_value = self._colorize(value, Color.RED)
                    elif 'failed' in key.lower() and value != '0':
                        display_value = self._colorize(value, Color.RED)
                    else:
                        display_value = value
                    
                    display_data.append([key, display_value])
        else:
            display_data.append(["Status", self._colorize("User systemd not running", Color.RED)])
            status_data["Status"] = "Not running"
        
        self.manager_status = status_data
        self._display_table("USER SYSTEMD MANAGER STATUS", ["Property", "Value"], display_data)
        
        return status_data
    
    def list_user_units(self, unit_type="service"):
        units = []
        
        cmd = ['systemctl', '--user', 'list-units', f'--type={unit_type}', '--no-pager', '--plain']
        output, code = self._run_user_command(cmd)
        
        if code != 0:
            self._warning(f"Failed to list {unit_type} units")
            return units
        
        lines = output.split('\n')
        header_found = False
        
        for line in lines:
            if not line.strip():
                continue
            
            if line.startswith('UNIT') and 'LOAD' in line and 'ACTIVE' in line and 'SUB' in line:
                header_found = True
                continue
            
            if header_found:
                parts = line.split()
                if len(parts) >= 5:
                    unit = SystemdUnit(
                        name=parts[0],
                        state="unknown",
                        load=parts[1],
                        active=parts[2],
                        sub=parts[3],
                        description=' '.join(parts[4:]) if len(parts) > 4 else ''
                    )
                    units.append(unit)
        
        cmd_files = ['systemctl', '--user', 'list-unit-files', f'--type={unit_type}', '--no-pager']
        output_files, _ = self._run_user_command(cmd_files)
        
        unit_states = {}
        for line in output_files.split('\n'):
            if line.strip() and not line.startswith('UNIT') and not line.startswith('unit files'):
                parts = line.split()
                if len(parts) >= 2:
                    unit_states[parts[0]] = parts[-1]
        
        for unit in units:
            if unit.name in unit_states:
                unit.state = unit_states[unit.name]
        
        display_data = []
        for unit in units[:20]:
            active_color = Color.GREEN if unit.active == 'active' else Color.RED
            display_data.append([
                unit.name,
                self._colorize(unit.load, Color.BLUE),
                self._colorize(unit.active, active_color),
                unit.sub,
                unit.description[:40] + "..." if len(unit.description) > 40 else unit.description
            ])
        
        headers = ["Unit", "Load", "Active", "Sub", "Description"]
        self._display_table(f"USER {unit_type.upper()} UNITS", headers, display_data)
        
        if len(units) > 20:
            print(f"... and {len(units) - 20} more {unit_type}s")
        
        if unit_type == "service":
            self.services = units
        elif unit_type == "socket":
            self.sockets = units
        
        return units
    
    def list_user_timers(self):
        cmd = ['systemctl', '--user', 'list-timers', '--all', '--no-pager']
        output, code = self._run_user_command(cmd)
        
        timers = []
        
        if code == 0:
            lines = output.split('\n')
            header_found = False
            
            for line in lines:
                if not line.strip():
                    continue
                
                if 'NEXT' in line and 'LEFT' in line and 'LAST' in line:
                    header_found = True
                    continue
                
                if header_found and not line.startswith('timers listed'):
                    parts = line.split()
                    if len(parts) >= 4:
                        timer = SystemdTimer(
                            name=parts[0],
                            next_activation=' '.join(parts[1:3]) if len(parts) >= 3 else parts[1],
                            time_left=parts[3] if len(parts) >= 4 else None,
                            last_activation=' '.join(parts[4:6]) if len(parts) >= 6 else None
                        )
                        timers.append(timer)
        
        display_data = []
        for timer in timers:
            display_data.append([
                timer.name,
                timer.next_activation or "N/A",
                timer.time_left or "N/A",
                timer.last_activation or "N/A"
            ])
        
        headers = ["Timer", "Next", "Left", "Last"]
        self._display_table("USER TIMER UNITS", headers, display_data)
        
        self.timers = timers
        return timers
    
    def check_linger_status(self):
        if not self.user_info:
            self.get_current_user()
        
        cmd = ['loginctl', 'show-user', self.user_info.name, '-p', 'Linger']
        output, code = self._run_command(cmd)
        
        linger = None
        if code == 0:
            for line in output.split('\n'):
                if line.startswith('Linger='):
                    linger = line.split('=')[1].strip() == 'yes'
                    break
        
        display_data = [[
            self.user_info.name,
            self._colorize("Enabled", Color.GREEN) if linger else 
            self._colorize("Disabled", Color.RED) if linger is False else "Unknown"
        ]]
        
        self._display_table("USER LINGER STATUS", ["Username", "Linger"], display_data)
        
        if self.user_info:
            self.user_info.linger = linger
        
        return linger
    
    def check_system_users(self):
        cmd = ['loginctl', 'list-users', '--no-pager']
        output, code = self._run_command(cmd)
        
        users = []
        if code == 0:
            lines = output.split('\n')
            for line in lines:
                if line.strip() and not line.startswith('UID'):
                    parts = line.split()
                    if len(parts) >= 3:
                        users.append({
                            'uid': parts[0],
                            'user': parts[1],
                            'sessions': parts[2]
                        })
        
        display_data = []
        for user in users:
            is_current = user['user'] == self.user_info.name
            user_display = self._colorize(user['user'], Color.CYAN) if is_current else user['user']
            display_data.append([user['uid'], user_display, user['sessions']])
        
        self._display_table("SYSTEM USERS WITH SESSIONS", ["UID", "User", "Sessions"], display_data)
        
        return users
    
    def check_cgroup_resources(self):
        cmd = ['systemd-cgls', '--user', '--no-pager']
        output, code = self._run_user_command(cmd)
        
        stats = {
            'services': 0,
            'slices': 0,
            'scopes': 0,
            'processes': 0
        }
        
        if code == 0:
            lines = output.split('\n')
            for line in lines:
                if '.service' in line:
                    stats['services'] += 1
                elif '.slice' in line:
                    stats['slices'] += 1
                elif '.scope' in line:
                    stats['scopes'] += 1
                if '├─' in line or '└─' in line:
                    stats['processes'] += 1
        
        display_data = [
            ["Services", str(stats['services'])],
            ["Slices", str(stats['slices'])],
            ["Scopes", str(stats['scopes'])],
            ["Processes", str(stats['processes'])]
        ]
        
        self._display_table("USER CGROUP RESOURCES", ["Resource", "Count"], display_data)
        
        return stats
    
    def _display_table(self, title, headers, data):
        print(f"\n{self._colorize('=' * 80, Color.BOLD)}")
        print(f"{self._colorize(title.center(80), Color.BOLD)}")
        print(f"{self._colorize('=' * 80, Color.BOLD)}")
        
        if not data:
            print("No data available")
            return
        
        if HAS_TABULATE:
            print(tabulate(data, headers=headers, tablefmt="simple"))
        else:
            col_widths = [len(h) for h in headers]
            for row in data:
                for i, cell in enumerate(row):
                    col_widths[i] = max(col_widths[i], len(str(cell)))
            
            header_row = " | ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers))
            print(header_row)
            print("-" * len(header_row))
            
            for row in data:
                print(" | ".join(str(cell).ljust(col_widths[i]) for i, cell in enumerate(row)))
    
    def generate_summary(self):
        if not self.user_info:
            self.get_current_user()
        
        summary = {
            'user': {
                'name': self.user_info.name,
                'uid': self.user_info.uid,
                'linger': self.user_info.linger
            },
            'directories': {
                'config_exists': any(d.exists for d in self.directories if "Config" in d.name),
                'total_units': sum(d.unit_count for d in self.directories if d.unit_count > 0)
            },
            'services': {
                'total': len(self.services),
                'active': len([s for s in self.services if s.active == 'active']),
                'failed': len([s for s in self.services if s.active == 'failed'])
            },
            'sockets': {
                'total': len(self.sockets),
                'active': len([s for s in self.sockets if s.active == 'active'])
            },
            'timers': {
                'total': len(self.timers)
            },
            'manager': {
                'running': 'running' in str(self.manager_status.get('State', '')).lower()
            }
        }
        
        display_data = [
            ["User", f"{summary['user']['name']} (UID: {summary['user']['uid']})"],
            ["Linger", 
             self._colorize("Enabled", Color.GREEN) if summary['user']['linger'] 
             else self._colorize("Disabled", Color.YELLOW) if summary['user']['linger'] is False 
             else "Unknown"],
            ["Config Dir", 
             self._colorize("Exists", Color.GREEN) if summary['directories']['config_exists'] 
             else self._colorize("Missing", Color.RED)],
            ["Total Units", str(summary['directories']['total_units'])],
            ["Services", f"{summary['services']['active']} active / {summary['services']['total']} total"],
            ["Sockets", f"{summary['sockets']['active']} active / {summary['sockets']['total']} total"],
            ["Timers", str(summary['timers']['total'])],
            ["Manager", 
             self._colorize("Running", Color.GREEN) if summary['manager']['running'] 
             else self._colorize("Not Running", Color.RED)]
        ]
        
        self._display_table("SUMMARY", ["Component", "Status"], display_data)
        
        self.summary = summary
        return summary
    
    def export_json(self, filename="user_process_mgmt.json"):
        data = {
            'user_info': asdict(self.user_info) if self.user_info else None,
            'directories': [asdict(d) for d in self.directories],
            'services': [asdict(s) for s in self.services],
            'sockets': [asdict(s) for s in self.sockets],
            'timers': [asdict(t) for t in self.timers],
            'manager_status': self.manager_status,
            'summary': self.summary
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            print(f"\n{self._colorize('✓', Color.GREEN)} Data exported to {filename}")
            return True
        except Exception as e:
            self._error(f"Failed to export JSON: {e}")
            return False
    
    def run_checks(self):
        print(f"\n{self._colorize('SYSTEMD USER PROCESS MANAGEMENT ANALYSIS', Color.BOLD + Color.CYAN)}")
        print(f"{self._colorize('=' * 80, Color.BOLD)}\n")
        
        self.get_current_user()
        self.check_user_directories()
        self.check_systemd_manager()
        self.list_user_units("service")
        self.list_user_units("socket")
        self.list_user_timers()
        self.check_linger_status()
        self.check_system_users()
        self.check_cgroup_resources()
        self.generate_summary()
        
        return {
            'user_info': self.user_info,
            'summary': self.summary,
            'services': self.services,
            'sockets': self.sockets
        }


def print_help_commands():
    commands = [
        ("Check user systemd status", "systemctl --user status"),
        ("Start a user service", "systemctl --user start <service>"),
        ("Stop a user service", "systemctl --user stop <service>"),
        ("Enable service at login", "systemctl --user enable <service>"),
        ("Disable service", "systemctl --user disable <service>"),
        ("Reload unit files", "systemctl --user daemon-reload"),
        ("View user journal", "journalctl --user -f"),
        ("Enable lingering", "loginctl enable-linger $USER"),
        ("Disable lingering", "loginctl disable-linger $USER"),
        ("List user units", "systemctl --user list-units"),
        ("Check failed units", "systemctl --user --failed"),
    ]
    
    print(f"\n{Color.BOLD}Common Systemd User Commands:{Color.RESET}")
    print(f"{Color.BLUE}{'=' * 60}{Color.RESET}")
    
    for desc, cmd in commands:
        print(f"{Color.GREEN}{desc:<30}{Color.RESET} {Color.YELLOW}{cmd}{Color.RESET}")
    
    print(f"{Color.BLUE}{'=' * 60}{Color.RESET}")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Check systemd user process management',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output including journal errors')
    parser.add_argument('--json', '-j', action='store_true',
                       help='Export results to JSON')
    parser.add_argument('--output', '-o', default='user_process_mgmt.json',
                       help='Output JSON filename')
    parser.add_argument('--sample', '-s', action='store_true',
                       help='Create sample user service')
    parser.add_argument('--no-color', action='store_true',
                       help='Disable colored output')
    
    args = parser.parse_args()
    
    try:
        checker = SystemdUserChecker(
            verbose=args.verbose,
            color=not args.no_color
        )
        
        results = checker.run_checks()
        
        if args.sample:
            print("\n" + "="*80)
            print("SAMPLE SERVICE CREATION".center(80))
            print("="*80)
            print("To create a sample service, use: systemctl --user edit --full --force sample.service")
            print("Example service content:")
            print("[Unit]")
            print("Description=Sample Service")
            print("")
            print("[Service]")
            print("Type=simple")
            print("ExecStart=/usr/bin/sleep infinity")
            print("")
            print("[Install]")
            print("WantedBy=default.target")
        
        if args.json:
            checker.export_json(args.output)
        
        print_help_commands()
        
        if results['summary'] and results['summary'].get('manager', {}).get('running'):
            sys.exit(0)
        else:
            sys.exit(1)
            
    except KeyboardInterrupt:
        print(f"\n{Color.YELLOW}Interrupted by user{Color.RESET}")
        sys.exit(130)
    except Exception as e:
        print(f"{Color.RED}Error: {e}{Color.RESET}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
