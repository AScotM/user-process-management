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
import configparser
import time
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any, Union
from dataclasses import dataclass, asdict, field
from enum import Enum
from datetime import datetime
from contextlib import contextmanager

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


class ExitCode(Enum):
    SUCCESS = 0
    MANAGER_NOT_RUNNING = 1
    USER_ERROR = 2
    ENVIRONMENT_ERROR = 3
    PERMISSION_ERROR = 4
    TIMEOUT_ERROR = 124
    INTERRUPTED = 130


@dataclass
class UserInfo:
    name: str
    uid: int
    gid: int
    home: str
    groups: List[str]
    linger: Optional[bool] = None
    shell: Optional[str] = None
    gecos: Optional[str] = None


@dataclass
class SystemdDir:
    name: str
    path: Path
    exists: bool
    is_directory: bool
    unit_count: int = 0
    accessible: bool = True
    permission_issues: List[str] = field(default_factory=list)


@dataclass
class SystemdUnit:
    name: str
    state: str
    load: str = "unknown"
    active: str = "unknown"
    sub: str = "unknown"
    description: str = ""
    pid: Optional[int] = None
    memory_bytes: Optional[int] = None
    cpu_usage: Optional[float] = None


@dataclass
class SystemdTimer:
    name: str
    next_activation: Optional[str] = None
    time_left: Optional[str] = None
    last_activation: Optional[str] = None
    last_trigger: Optional[str] = None
    passes: Optional[int] = None


@dataclass
class CommandResult:
    stdout: str
    stderr: str
    returncode: int
    command: List[str]
    duration: float


class ProgressIndicator:
    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self.current_step = 0
        self.total_steps = 0
        self.start_time = None
    
    def start(self, total_steps: int, description: str = "Processing"):
        self.total_steps = total_steps
        self.current_step = 0
        self.start_time = time.time()
        if self.enabled:
            print(f"\n{Color.CYAN}Starting: {description}{Color.RESET}")
    
    def update(self, step_description: str = ""):
        self.current_step += 1
        if self.enabled and self.total_steps > 0:
            percentage = (self.current_step / self.total_steps) * 100
            elapsed = time.time() - self.start_time if self.start_time else 0
            bar_length = 30
            filled = int(bar_length * self.current_step // self.total_steps)
            bar = '█' * filled + '░' * (bar_length - filled)
            print(f"\r{Color.BLUE}[{bar}] {percentage:.1f}% ({self.current_step}/{self.total_steps}) {step_description} [{elapsed:.1f}s]{Color.RESET}", end='')
    
    def finish(self, success: bool = True):
        if self.enabled:
            elapsed = time.time() - self.start_time if self.start_time else 0
            status = f"{Color.GREEN}Completed{Color.RESET}" if success else f"{Color.RED}Failed{Color.RESET}"
            print(f"\n{status} in {elapsed:.2f} seconds\n")


class ConfigManager:
    def __init__(self, config_path: Optional[Path] = None):
        if config_path:
            self.config_path = Path(config_path)
        else:
            xdg_config = os.environ.get('XDG_CONFIG_HOME')
            if xdg_config:
                self.config_path = Path(xdg_config) / "systemd-checker" / "config.ini"
            else:
                self.config_path = Path.home() / ".config" / "systemd-checker" / "config.ini"
        
        self.config = configparser.ConfigParser()
        self.default_config = {
            'general': {
                'timeout': '30',
                'max_units_display': '20',
                'color': 'true',
                'progress': 'true',
                'max_command_history': '100'
            },
            'paths': {
                'user_config': '.config/systemd/user',
                'user_local': '.local/share/systemd/user',
                'system_user': '/usr/lib/systemd/user',
                'system_local': '/usr/local/lib/systemd/user'
            },
            'filters': {
                'exclude_services': '',
                'include_only': '',
                'show_failed_only': 'false'
            },
            'export': {
                'json_indent': '2',
                'default_filename': 'user_process_mgmt.json'
            }
        }
        self.load_config()
    
    def load_config(self) -> None:
        if self.config_path.exists():
            try:
                self.config.read(self.config_path)
            except Exception as e:
                print(f"{Color.YELLOW}Warning: Could not load config {self.config_path}: {e}{Color.RESET}")
                self._create_default_config()
        else:
            self._create_default_config()
    
    def _create_default_config(self) -> None:
        for section, options in self.default_config.items():
            if not self.config.has_section(section):
                self.config.add_section(section)
            for key, value in options.items():
                self.config.set(section, key, value)
        
        try:
            config_dir = self.config_path.parent
            if not config_dir.exists():
                config_dir.mkdir(parents=True, exist_ok=True)
            
            test_file = config_dir / '.write_test'
            test_file.touch()
            test_file.unlink()
            
            with open(self.config_path, 'w') as f:
                self.config.write(f)
        except (PermissionError, OSError) as e:
            self.config = configparser.ConfigParser()
            for section, options in self.default_config.items():
                self.config.add_section(section)
                for key, value in options.items():
                    self.config.set(section, key, value)
            print(f"{Color.YELLOW}Using in-memory configuration (cannot write to {config_dir}){Color.RESET}")
    
    def get(self, section: str, key: str, fallback: Any = None) -> str:
        try:
            return self.config.get(section, key, fallback=fallback)
        except:
            return self.default_config.get(section, {}).get(key, fallback)
    
    def get_int(self, section: str, key: str, fallback: int = 0) -> int:
        try:
            value = self.config.get(section, key, fallback=str(fallback))
            try:
                return int(value)
            except ValueError:
                return fallback
        except:
            default_value = self.default_config.get(section, {}).get(key, str(fallback))
            try:
                return int(default_value)
            except ValueError:
                return fallback
    
    def get_bool(self, section: str, key: str, fallback: bool = False) -> bool:
        try:
            value = self.config.get(section, key, fallback=str(fallback)).lower()
            return value in ('true', 'yes', 'on', '1')
        except:
            default_value = self.default_config.get(section, {}).get(key, str(fallback)).lower()
            return default_value in ('true', 'yes', 'on', '1')


class SystemdUserChecker:
    def __init__(self, verbose: bool = False, color: bool = True, progress: bool = True, config: Optional[ConfigManager] = None):
        self.verbose = verbose
        self.use_color = color and sys.stdout.isatty()
        self.show_progress = progress
        self.config = config or ConfigManager()
        self.logger = self._setup_logger()
        self.user_info = None
        self.directories = []
        self.services = []
        self.sockets = []
        self.timers = []
        self.manager_status = {}
        self.summary = {}
        self.progress = ProgressIndicator(enabled=self.show_progress)
        self.command_history: List[CommandResult] = []
        self.max_command_history = self.config.get_int('general', 'max_command_history', 100)
        self._process_cache = {}
        self._process_cache_time = 0
        self._validate_environment()
    
    def _setup_logger(self) -> logging.Logger:
        logger = logging.getLogger(__name__)
        if not logger.handlers:
            handler = logging.StreamHandler(sys.stderr)
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.DEBUG if self.verbose else logging.WARNING)
        return logger
    
    def _validate_environment(self) -> None:
        if platform.system() != 'Linux':
            self._error("This tool only works on Linux systems")
            sys.exit(ExitCode.ENVIRONMENT_ERROR.value)
        
        try:
            result = subprocess.run(
                ['systemctl', '--version'],
                capture_output=True,
                text=True,
                check=False,
                timeout=5
            )
            if result.returncode != 0:
                self._error("Systemd not found or not accessible")
                sys.exit(ExitCode.ENVIRONMENT_ERROR.value)
        except FileNotFoundError:
            self._error("systemctl command not found")
            sys.exit(ExitCode.ENVIRONMENT_ERROR.value)
        except subprocess.TimeoutExpired:
            self._error("systemctl command timed out")
            sys.exit(ExitCode.TIMEOUT_ERROR.value)
        
        if os.geteuid() == 0:
            self._warning("Running as root. Some user-specific checks may not work as expected.")
    
    def _colorize(self, text: str, color: str) -> str:
        if self.use_color:
            return f"{color}{text}{Color.RESET}"
        return text
    
    def _error(self, message: str) -> None:
        print(f"{self._colorize('Error:', Color.RED)} {message}", file=sys.stderr)
        self.logger.error(message)
    
    def _warning(self, message: str) -> None:
        print(f"{self._colorize('Warning:', Color.YELLOW)} {message}", file=sys.stderr)
        self.logger.warning(message)
    
    def _run_command(self, cmd_args: List[str], capture: bool = True, timeout: Optional[int] = None) -> CommandResult:
        start_time = time.time()
        timeout_value = timeout or self.config.get_int('general', 'timeout', 30)
        
        try:
            self.logger.debug(f"Running command: {' '.join(cmd_args)}")
            
            if capture:
                result = subprocess.run(
                    cmd_args,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=timeout_value
                )
                stdout = result.stdout.strip() if result.stdout else ""
                stderr = result.stderr.strip() if result.stderr else ""
                returncode = result.returncode
            else:
                result = subprocess.run(
                    cmd_args,
                    check=False,
                    timeout=timeout_value
                )
                stdout = ""
                stderr = ""
                returncode = result.returncode
            
            duration = time.time() - start_time
            cmd_result = CommandResult(
                stdout=stdout,
                stderr=stderr,
                returncode=returncode,
                command=cmd_args,
                duration=duration
            )
            
            self.command_history.append(cmd_result)
            if len(self.command_history) > self.max_command_history:
                self.command_history.pop(0)
            
            return cmd_result
            
        except subprocess.TimeoutExpired:
            self._warning(f"Command timed out after {timeout_value}s: {' '.join(cmd_args)}")
            return CommandResult(
                stdout="",
                stderr=f"Command timed out after {timeout_value} seconds",
                returncode=ExitCode.TIMEOUT_ERROR.value,
                command=cmd_args,
                duration=timeout_value
            )
        except Exception as e:
            self.logger.error(f"Command failed: {e}")
            return CommandResult(
                stdout="",
                stderr=str(e),
                returncode=1,
                command=cmd_args,
                duration=time.time() - start_time
            )
    
    def _run_user_command(self, cmd_args: List[str]) -> CommandResult:
        if os.getuid() == self.user_info.uid:
            return self._run_command(cmd_args)
        
        if os.geteuid() != 0:
            self._warning(f"Not running as root, attempting sudo for user {self.user_info.name}")
        
        unsafe_commands = ['rm', 'mv', 'dd', 'format', 'mkfs', 'fdisk', 'chmod', 'chown']
        if any(unsafe_cmd in ' '.join(cmd_args).lower() for unsafe_cmd in unsafe_commands):
            self._error(f"Potentially unsafe command blocked: {cmd_args}")
            return CommandResult(
                stdout="",
                stderr="Command blocked for security",
                returncode=1,
                command=cmd_args,
                duration=0
            )
        
        user_cmd = ['sudo', '-n', '-u', self.user_info.name] + cmd_args
        return self._run_command(user_cmd)
    
    def _get_user_processes(self) -> Dict[str, Dict]:
        if not HAS_PSUTIL:
            return {}
        
        current_time = time.time()
        if current_time - self._process_cache_time < 5:
            return self._process_cache
        
        process_map = {}
        try:
            for proc in psutil.process_iter(['pid', 'name', 'username', 'memory_info', 'cpu_percent'], timeout=2):
                try:
                    if proc.info['username'] == self.user_info.name:
                        process_map[str(proc.info['pid'])] = {
                            'name': proc.info['name'],
                            'pid': proc.info['pid'],
                            'memory': proc.info['memory_info'].rss if proc.info['memory_info'] else None,
                            'cpu': proc.info['cpu_percent']
                        }
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired):
                    continue
        except Exception as e:
            self.logger.warning(f"Process iteration failed: {e}")
        
        self._process_cache = process_map
        self._process_cache_time = current_time
        return process_map
    
    def _display_user_info(self) -> None:
        if not self.user_info:
            return
        
        try:
            pw_entry = pwd.getpwnam(self.user_info.name)
            shell = pw_entry.pw_shell
            gecos = pw_entry.pw_gecos.split(',')[0] if pw_entry.pw_gecos else ""
        except:
            shell = "Unknown"
            gecos = ""
        
        data = [
            ["Username", self.user_info.name],
            ["User ID", str(self.user_info.uid)],
            ["Group ID", str(self.user_info.gid)],
            ["Home Directory", self.user_info.home],
            ["Shell", shell],
            ["Full Name", gecos if gecos else "N/A"],
            ["Groups", ", ".join(self.user_info.groups[:10]) + 
             ("..." if len(self.user_info.groups) > 10 else "")]
        ]
        
        self._display_table("CURRENT USER INFORMATION", ["Property", "Value"], data)
    
    def get_current_user(self) -> UserInfo:
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
                groups=groups,
                shell=pw_entry.pw_shell,
                gecos=pw_entry.pw_gecos.split(',')[0] if pw_entry.pw_gecos else None
            )
            
            self._display_user_info()
            return self.user_info
            
        except Exception as e:
            self._error(f"Failed to get user info: {e}")
            sys.exit(ExitCode.USER_ERROR.value)
    
    def check_user_directories(self) -> List[SystemdDir]:
        if not self.user_info:
            self.get_current_user()
        
        dir_configs = [
            ("User Config", Path(self.user_info.home) / self.config.get('paths', 'user_config', '.config/systemd/user')),
            ("User Runtime", Path(f"/run/user/{self.user_info.uid}")),
            ("User Local", Path(self.user_info.home) / self.config.get('paths', 'user_local', '.local/share/systemd/user')),
            ("System User", Path(self.config.get('paths', 'system_user', '/usr/lib/systemd/user'))),
            ("System Local", Path(self.config.get('paths', 'system_local', '/usr/local/lib/systemd/user')))
        ]
        
        dir_objects = []
        display_data = []
        
        for name, path in dir_configs:
            exists = path.exists()
            is_dir = path.is_dir() if exists else False
            unit_count = 0
            accessible = True
            permission_issues = []
            
            if exists and is_dir:
                try:
                    unit_extensions = ['.service', '.socket', '.timer', '.target', '.mount', '.automount', '.path', '.slice']
                    for ext in unit_extensions:
                        unit_count += sum(1 for _ in path.glob(f"*{ext}"))
                    
                    if not os.access(path, os.R_OK):
                        accessible = False
                        permission_issues.append("read permission denied")
                    if not os.access(path, os.X_OK):
                        accessible = False
                        permission_issues.append("execute permission denied")
                        
                except PermissionError:
                    accessible = False
                    permission_issues.append("permission denied")
                except Exception as e:
                    self._warning(f"Could not scan {path}: {e}")
                    accessible = False
                    permission_issues.append(str(e))
            
            dir_obj = SystemdDir(
                name=name,
                path=path,
                exists=exists,
                is_directory=is_dir,
                unit_count=unit_count,
                accessible=accessible,
                permission_issues=permission_issues
            )
            dir_objects.append(dir_obj)
            
            if not exists:
                status = self._colorize("Missing", Color.RED)
            elif not accessible:
                status = self._colorize(f"Access Denied ({', '.join(permission_issues)})", Color.YELLOW)
            elif unit_count > 0:
                status = self._colorize(f"Present ({unit_count} units)", Color.GREEN)
            else:
                status = self._colorize("Present (empty)", Color.BLUE)
            
            display_data.append([name, str(path), status])
        
        self.directories = dir_objects
        self._display_table("USER SYSTEMD DIRECTORIES", ["Directory", "Path", "Status"], display_data)
        
        return dir_objects
    
    def check_systemd_manager(self) -> Dict[str, str]:
        result = self._run_user_command(['systemctl', '--user', '--no-pager', 'status'])
        
        status_data = {}
        display_data = []
        
        if result.returncode == 0:
            lines = result.stdout.split('\n')
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
                    elif key == 'PID':
                        display_value = self._colorize(value, Color.CYAN)
                    else:
                        display_value = value
                    
                    display_data.append([key, display_value])
        else:
            error_msg = "User systemd not running"
            if result.stderr:
                error_msg += f" - {result.stderr[:100]}"
            display_data.append(["Status", self._colorize(error_msg, Color.RED)])
            status_data["Status"] = "Not running"
            status_data["Error"] = result.stderr
        
        self.manager_status = status_data
        self._display_table("USER SYSTEMD MANAGER STATUS", ["Property", "Value"], display_data)
        
        return status_data
    
    def list_user_units(self, unit_type: str = "service") -> List[SystemdUnit]:
        units = []
        
        cmd = ['systemctl', '--user', 'list-units', f'--type={unit_type}', '--no-pager', '--plain', '--full']
        result = self._run_user_command(cmd)
        
        if result.returncode != 0:
            self._warning(f"Failed to list {unit_type} units: {result.stderr}")
            return units
        
        process_map = self._get_user_processes()
        
        lines = result.stdout.split('\n')
        header_found = False
        
        for line in lines:
            if not line.strip():
                continue
            
            if line.startswith('UNIT') and 'LOAD' in line and 'ACTIVE' in line and 'SUB' in line:
                header_found = True
                continue
            
            if header_found and not line.startswith('●'):
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
                    
                    if unit_type == "service":
                        pid_cmd = ['systemctl', '--user', 'show', parts[0], '--property=MainPID', '--no-pager']
                        pid_result = self._run_user_command(pid_cmd)
                        if pid_result.returncode == 0 and 'MainPID=' in pid_result.stdout:
                            pid_str = pid_result.stdout.strip().split('=')[1]
                            if pid_str and pid_str != '0':
                                unit.pid = int(pid_str)
                                if str(unit.pid) in process_map:
                                    proc_info = process_map[str(unit.pid)]
                                    unit.memory_bytes = proc_info.get('memory')
                                    unit.cpu_usage = proc_info.get('cpu')
                    
                    units.append(unit)
        
        cmd_files = ['systemctl', '--user', 'list-unit-files', f'--type={unit_type}', '--no-pager', '--full']
        result_files = self._run_user_command(cmd_files)
        
        unit_states = {}
        for line in result_files.stdout.split('\n'):
            if line.strip() and not line.startswith('UNIT') and not line.startswith('unit files'):
                parts = line.split()
                if len(parts) >= 2:
                    unit_states[parts[0]] = parts[-1]
        
        for unit in units:
            if unit.name in unit_states:
                unit.state = unit_states[unit.name]
        
        max_display = self.config.get_int('general', 'max_units_display', 20)
        show_failed_only = self.config.get_bool('filters', 'show_failed_only', False)
        
        display_units = units
        if show_failed_only:
            display_units = [u for u in units if u.active == 'failed']
        
        display_data = []
        for unit in display_units[:max_display]:
            active_color = Color.GREEN if unit.active == 'active' else Color.RED if unit.active == 'failed' else Color.YELLOW
            state_display = unit.state
            
            if unit.pid:
                state_display += f" (PID:{unit.pid})"
            if unit.memory_bytes:
                memory_mb = unit.memory_bytes / (1024 * 1024)
                state_display += f" Mem:{memory_mb:.1f}MB"
            
            display_data.append([
                unit.name,
                self._colorize(unit.load, Color.BLUE),
                self._colorize(unit.active, active_color),
                unit.sub,
                unit.description[:40] + "..." if len(unit.description) > 40 else unit.description,
                state_display
            ])
        
        headers = ["Unit", "Load", "Active", "Sub", "Description", "State/Resources"]
        self._display_table(f"USER {unit_type.upper()} UNITS ({'failed only' if show_failed_only else 'all'})", headers, display_data)
        
        if len(display_units) > max_display:
            print(f"... and {len(display_units) - max_display} more {unit_type}s")
        
        if unit_type == "service":
            self.services = units
        elif unit_type == "socket":
            self.sockets = units
        
        return units
    
    def list_user_timers(self) -> List[SystemdTimer]:
        cmd = ['systemctl', '--user', 'list-timers', '--all', '--no-pager', '--full']
        result = self._run_user_command(cmd)
        
        timers = []
        
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            header_found = False
            
            for line in lines:
                if not line.strip():
                    continue
                
                if 'NEXT' in line and 'LEFT' in line and 'LAST' in line and 'PASSED' in line:
                    header_found = True
                    continue
                
                if header_found and not line.startswith('timers listed'):
                    parts = line.split()
                    if len(parts) >= 6:
                        timer = SystemdTimer(
                            name=parts[0],
                            next_activation=' '.join(parts[1:3]),
                            time_left=parts[3],
                            last_activation=' '.join(parts[4:6]),
                            last_trigger=parts[6] if len(parts) > 6 else None,
                            passes=int(parts[7]) if len(parts) > 7 and parts[7].isdigit() else None
                        )
                        timers.append(timer)
        
        display_data = []
        for timer in timers:
            display_data.append([
                timer.name,
                timer.next_activation or "N/A",
                timer.time_left or "N/A",
                timer.last_activation or "N/A",
                timer.passes or "N/A"
            ])
        
        headers = ["Timer", "Next", "Left", "Last", "Passes"]
        self._display_table("USER TIMER UNITS", headers, display_data)
        
        self.timers = timers
        return timers
    
    def check_linger_status(self) -> Optional[bool]:
        if not self.user_info:
            self.get_current_user()
        
        cmd = ['loginctl', 'show-user', self.user_info.name, '-p', 'Linger']
        result = self._run_command(cmd)
        
        linger = None
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if line.startswith('Linger='):
                    linger = line.split('=')[1].strip() == 'yes'
                    break
        
        sessions = []
        cmd_sessions = ['loginctl', 'list-sessions', '--no-pager']
        result_sessions = self._run_command(cmd_sessions)
        
        for line in result_sessions.stdout.split('\n'):
            if self.user_info.name in line:
                parts = line.split()
                if len(parts) >= 3:
                    sessions.append({
                        'session': parts[0],
                        'uid': parts[1],
                        'user': parts[2],
                        'seat': parts[3] if len(parts) > 3 else 'none'
                    })
        
        display_data = [[
            self.user_info.name,
            self._colorize("Enabled", Color.GREEN) if linger else 
            self._colorize("Disabled", Color.YELLOW) if linger is False else self._colorize("Unknown", Color.RED),
            str(len(sessions))
        ]]
        
        self._display_table("USER LINGER STATUS", ["Username", "Linger", "Active Sessions"], display_data)
        
        if self.user_info:
            self.user_info.linger = linger
        
        return linger
    
    def check_system_users(self) -> List[Dict[str, str]]:
        if not self.user_info:
            self.get_current_user()
            
        cmd = ['loginctl', 'list-users', '--no-pager']
        result = self._run_command(cmd)
        
        users = []
        if result.returncode == 0:
            lines = result.stdout.split('\n')
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
            
            try:
                sessions_count = int(user['sessions'])
                sessions_display = self._colorize(user['sessions'], Color.GREEN) if sessions_count > 0 else self._colorize(user['sessions'], Color.YELLOW)
            except ValueError:
                sessions_display = user['sessions']
            
            display_data.append([user['uid'], user_display, sessions_display])
        
        self._display_table("SYSTEM USERS WITH SESSIONS", ["UID", "User", "Sessions"], display_data)
        
        return users
    
    def check_cgroup_resources(self) -> Dict[str, int]:
        cmd = ['systemd-cgls', '--user', '--no-pager']
        result = self._run_user_command(cmd)
        
        stats = {
            'services': 0,
            'slices': 0,
            'scopes': 0,
            'processes': 0
        }
        
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            for line in lines:
                if '.service' in line:
                    stats['services'] += 1
                elif '.slice' in line:
                    stats['slices'] += 1
                elif '.scope' in line:
                    stats['scopes'] += 1
                if '├─' in line or '└─' in line:
                    stats['processes'] += 1
        
        if HAS_PSUTIL and self.user_info:
            user_procs = 0
            process_map = self._get_user_processes()
            user_procs = len(process_map)
            stats['user_processes'] = user_procs
        
        display_data = [
            ["Services", str(stats['services'])],
            ["Slices", str(stats['slices'])],
            ["Scopes", str(stats['scopes'])],
            ["CGroup Processes", str(stats['processes'])]
        ]
        
        if HAS_PSUTIL:
            display_data.append(["Total User Processes", str(stats.get('user_processes', 0))])
        
        self._display_table("USER CGROUP RESOURCES", ["Resource", "Count"], display_data)
        
        return stats
    
    def check_journal_errors(self, lines: int = 20) -> List[Dict[str, str]]:
        cmd = ['journalctl', '--user', '-p', '3', '-n', str(lines), '--no-pager']
        result = self._run_user_command(cmd)
        
        errors = []
        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.split('\n')[:lines]:
                if line.strip():
                    errors.append({
                        'message': line[:100] + '...' if len(line) > 100 else line,
                        'full': line
                    })
        
        if errors:
            display_data = [[e['message']] for e in errors]
            self._display_table(f"RECENT USER JOURNAL ERRORS (last {len(errors)})", ["Error Message"], display_data)
        
        return errors
    
    def show_service_dependencies(self, service_name: str) -> None:
        if not service_name or '..' in service_name or '/' in service_name:
            self._error("Invalid service name")
            return
        
        check_cmd = ['systemctl', '--user', 'list-units', service_name, '--no-pager']
        check_result = self._run_user_command(check_cmd)
        if check_result.returncode != 0 or service_name not in check_result.stdout:
            self._error(f"Service '{service_name}' not found")
            return
        
        cmd = ['systemctl', '--user', 'list-dependencies', service_name]
        result = self._run_user_command(cmd)
        
        if result.returncode == 0 and result.stdout.strip():
            dependencies = []
            for line in result.stdout.split('\n'):
                if line.strip() and not line.startswith(service_name):
                    dependencies.append([line.strip()])
            
            if dependencies:
                self._display_table(f"DEPENDENCIES FOR {service_name}", ["Dependency"], dependencies)
            else:
                print(f"{self._colorize('No dependencies found', Color.YELLOW)}")
    
    def _display_table(self, title: str, headers: List[str], data: List[List[Any]]) -> None:
        print(f"\n{self._colorize('=' * 80, Color.BOLD)}")
        print(f"{self._colorize(title.center(80), Color.BOLD)}")
        print(f"{self._colorize('=' * 80, Color.BOLD)}")
        
        if not data:
            print(self._colorize("No data available", Color.YELLOW))
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
                formatted_row = []
                for i, cell in enumerate(row):
                    if isinstance(cell, str) and self.use_color and cell.startswith('\033'):
                        formatted_row.append(cell)
                    else:
                        formatted_row.append(str(cell).ljust(col_widths[i]))
                print(" | ".join(formatted_row))
    
    def generate_summary(self) -> Dict[str, Any]:
        if not self.user_info:
            self.get_current_user()
        
        total_units = sum(d.unit_count for d in self.directories if d.unit_count > 0)
        config_exists = any(d.exists for d in self.directories if "Config" in d.name)
        
        summary = {
            'user': {
                'name': self.user_info.name,
                'uid': self.user_info.uid,
                'linger': self.user_info.linger
            },
            'directories': {
                'config_exists': config_exists,
                'total_units': total_units,
                'accessible_dirs': len([d for d in self.directories if d.accessible])
            },
            'services': {
                'total': len(self.services),
                'active': len([s for s in self.services if s.active == 'active']),
                'failed': len([s for s in self.services if s.active == 'failed']),
                'inactive': len([s for s in self.services if s.active == 'inactive'])
            },
            'sockets': {
                'total': len(self.sockets),
                'active': len([s for s in self.sockets if s.active == 'active']),
                'listening': len([s for s in self.sockets if s.sub == 'listening'])
            },
            'timers': {
                'total': len(self.timers)
            },
            'manager': {
                'running': 'running' in str(self.manager_status.get('State', '')).lower(),
                'pid': self.manager_status.get('PID', 'unknown')
            },
            'performance': {
                'command_count': len(self.command_history),
                'total_duration': sum(c.duration for c in self.command_history)
            }
        }
        
        if summary['services']['total'] > 0:
            summary['services']['active_percent'] = round((summary['services']['active'] / summary['services']['total']) * 100, 1)
        else:
            summary['services']['active_percent'] = 0
        
        display_data = [
            ["User", f"{summary['user']['name']} (UID: {summary['user']['uid']})"],
            ["Linger", 
             self._colorize("Enabled", Color.GREEN) if summary['user']['linger'] 
             else self._colorize("Disabled", Color.YELLOW) if summary['user']['linger'] is False 
             else self._colorize("Unknown", Color.RED)],
            ["Config Dir", 
             self._colorize("Exists", Color.GREEN) if summary['directories']['config_exists'] 
             else self._colorize("Missing", Color.RED)],
            ["Total Unit Files", str(summary['directories']['total_units'])],
            ["Services", f"{summary['services']['active']} active, {summary['services']['failed']} failed ({summary['services']['active_percent']}%)"],
            ["Sockets", f"{summary['sockets']['active']} active / {summary['sockets']['total']} total"],
            ["Timers", str(summary['timers']['total'])],
            ["Manager", 
             self._colorize("Running", Color.GREEN) if summary['manager']['running'] 
             else self._colorize("Not Running", Color.RED)],
            ["Manager PID", summary['manager']['pid'] if summary['manager']['pid'] != 'unknown' else 'N/A']
        ]
        
        self._display_table("SUMMARY", ["Component", "Status"], display_data)
        
        self.summary = summary
        return summary
    
    def export_json(self, filename: str = "user_process_mgmt.json") -> bool:
        filename_path = Path(filename)
        
        if filename_path.suffix.lower() not in ['.json']:
            filename_path = filename_path.with_suffix('.json')
            self._warning(f"Added .json extension: {filename_path}")
        
        parent = filename_path.parent
        if not parent.exists():
            try:
                parent.mkdir(parents=True, exist_ok=True)
            except PermissionError as e:
                self._error(f"Cannot create directory {parent}: {e}")
                return False
        
        data = {
            'generated': datetime.now().isoformat(),
            'version': '1.2.1',
            'user_info': asdict(self.user_info) if self.user_info else None,
            'directories': [asdict(d) for d in self.directories],
            'services': [asdict(s) for s in self.services],
            'sockets': [asdict(s) for s in self.sockets],
            'timers': [asdict(t) for t in self.timers],
            'manager_status': self.manager_status,
            'summary': self.summary,
            'command_stats': {
                'total_commands': len(self.command_history),
                'total_duration': sum(c.duration for c in self.command_history),
                'failed_commands': len([c for c in self.command_history if c.returncode != 0])
            }
        }
        
        try:
            json_indent = self.config.get_int('export', 'json_indent', 2)
            with open(filename_path, 'w') as f:
                json.dump(data, f, indent=json_indent, default=str)
            print(f"\n{self._colorize('✓', Color.GREEN)} Data exported to {filename_path}")
            return True
        except Exception as e:
            self._error(f"Failed to export JSON: {e}")
            return False
    
    def run_checks(self) -> Dict[str, Any]:
        print(f"\n{self._colorize('SYSTEMD USER PROCESS MANAGEMENT ANALYSIS', Color.BOLD + Color.CYAN)}")
        print(f"{self._colorize('Version 1.2.1', Color.BLUE)}")
        print(f"{self._colorize('=' * 80, Color.BOLD)}\n")
        
        self.progress.start(9, "Analyzing user systemd configuration")
        
        self.progress.update("Getting user information")
        self.get_current_user()
        
        self.progress.update("Checking systemd directories")
        self.check_user_directories()
        
        self.progress.update("Checking systemd manager status")
        self.check_systemd_manager()
        
        self.progress.update("Listing user services")
        self.list_user_units("service")
        
        self.progress.update("Listing user sockets")
        self.list_user_units("socket")
        
        self.progress.update("Listing user timers")
        self.list_user_timers()
        
        self.progress.update("Checking linger status")
        self.check_linger_status()
        
        self.progress.update("Checking system users")
        self.check_system_users()
        
        self.progress.update("Checking cgroup resources")
        self.check_cgroup_resources()
        
        if self.verbose:
            self.progress.update("Checking journal errors")
            self.check_journal_errors()
        
        self.progress.update("Generating summary")
        self.generate_summary()
        
        self.progress.finish(success=True)
        
        return {
            'user_info': self.user_info,
            'summary': self.summary,
            'services': self.services,
            'sockets': self.sockets
        }


def print_help_commands() -> None:
    commands = [
        ("Check user systemd status", "systemctl --user status"),
        ("Start a user service", "systemctl --user start <service>"),
        ("Stop a user service", "systemctl --user stop <service>"),
        ("Restart a user service", "systemctl --user restart <service>"),
        ("Enable service at login", "systemctl --user enable <service>"),
        ("Disable service", "systemctl --user disable <service>"),
        ("Reload unit files", "systemctl --user daemon-reload"),
        ("View user journal", "journalctl --user -f"),
        ("View failed units", "systemctl --user --failed"),
        ("Enable lingering", "loginctl enable-linger $USER"),
        ("Disable lingering", "loginctl disable-linger $USER"),
        ("List all user units", "systemctl --user list-units"),
        ("List unit files", "systemctl --user list-unit-files"),
        ("Show service logs", "journalctl --user -u <service>"),
        ("Reset failed units", "systemctl --user reset-failed")
    ]
    
    print(f"\n{Color.BOLD}Common Systemd User Commands:{Color.RESET}")
    print(f"{Color.BLUE}{'=' * 70}{Color.RESET}")
    
    for desc, cmd in commands:
        print(f"{Color.GREEN}{desc:<35}{Color.RESET} {Color.YELLOW}{cmd}{Color.RESET}")
    
    print(f"{Color.BLUE}{'=' * 70}{Color.RESET}")


def create_test_environment() -> None:
    print(f"\n{Color.BOLD}Creating Test Systemd User Environment{Color.RESET}")
    print(f"{Color.BLUE}{'=' * 60}{Color.RESET}")
    
    config_dir = Path.home() / ".config" / "systemd" / "user"
    config_dir.mkdir(parents=True, exist_ok=True)
    
    test_service = config_dir / "test.service"
    test_service.write_text("""[Unit]
Description=Test Service for Systemd User Checker
After=network.target

[Service]
Type=simple
ExecStart=/bin/sleep 3600
Restart=always
RestartSec=10

[Install]
WantedBy=default.target
""")
    
    test_timer = config_dir / "test.timer"
    test_timer.write_text("""[Unit]
Description=Test Timer for Systemd User Checker

[Timer]
OnBootSec=5min
OnUnitActiveSec=1hour

[Install]
WantedBy=timers.target
""")
    
    print(f"{Color.GREEN}✓{Color.RESET} Created test service: {test_service}")
    print(f"{Color.GREEN}✓{Color.RESET} Created test timer: {test_timer}")
    print(f"\n{Color.CYAN}To enable and start:{Color.RESET}")
    print("  systemctl --user daemon-reload")
    print("  systemctl --user enable --now test.service")
    print("  systemctl --user enable --now test.timer")


@contextmanager
def quiet_stderr():
    original_stderr = sys.stderr
    try:
        sys.stderr = open(os.devnull, 'w')
        yield
    except Exception:
        if sys.stderr is not original_stderr:
            sys.stderr.close()
        sys.stderr = original_stderr
        raise
    finally:
        if sys.stderr is not original_stderr:
            sys.stderr.close()
        sys.stderr = original_stderr


def main() -> None:
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Systemd User Process Management Analysis Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s                         Run all checks
  %(prog)s --verbose               Verbose output with journal errors
  %(prog)s --json --output report.json  Export results to JSON
  %(prog)s --sample                 Create sample user service
  %(prog)s --no-color --quiet       Run without colors and minimal output
  %(prog)s --test                   Create test environment
  %(prog)s --config /path/to/config.ini  Use custom config file
        '''
    )
    
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output including journal errors')
    parser.add_argument('--quiet', '-q', action='store_true',
                       help='Minimal output (only warnings and errors)')
    parser.add_argument('--json', '-j', action='store_true',
                       help='Export results to JSON')
    parser.add_argument('--output', '-o', default='user_process_mgmt.json',
                       help='Output JSON filename (default: user_process_mgmt.json)')
    parser.add_argument('--sample', '-s', action='store_true',
                       help='Show sample service creation instructions')
    parser.add_argument('--test', '-t', action='store_true',
                       help='Create test environment with sample units')
    parser.add_argument('--no-color', action='store_true',
                       help='Disable colored output')
    parser.add_argument('--no-progress', action='store_true',
                       help='Disable progress indicators')
    parser.add_argument('--config', '-c', type=str,
                       help='Path to configuration file')
    parser.add_argument('--failed-only', action='store_true',
                       help='Show only failed units')
    parser.add_argument('--unit-type', choices=['service', 'socket', 'timer', 'all'],
                       default='all', help='Specific unit type to analyze')
    parser.add_argument('--timeout', type=int,
                       help='Command timeout in seconds')
    parser.add_argument('--dependencies', '-d', type=str, metavar='SERVICE',
                       help='Show dependencies for a specific service')
    
    args = parser.parse_args()
    
    try:
        config = None
        if args.config:
            config = ConfigManager(Path(args.config))
        else:
            config = ConfigManager()
        
        if args.timeout:
            config.config.set('general', 'timeout', str(args.timeout))
        
        if args.failed_only:
            config.config.set('filters', 'show_failed_only', 'true')
        
        if args.test:
            create_test_environment()
            sys.exit(ExitCode.SUCCESS.value)
        
        if args.quiet:
            with quiet_stderr():
                checker = SystemdUserChecker(
                    verbose=args.verbose,
                    color=not args.no_color,
                    progress=not args.no_progress,
                    config=config
                )
                results = checker.run_checks()
        else:
            checker = SystemdUserChecker(
                verbose=args.verbose,
                color=not args.no_color,
                progress=not args.no_progress,
                config=config
            )
            results = checker.run_checks()
        
        if args.dependencies:
            checker.show_service_dependencies(args.dependencies)
        
        if args.sample:
            print("\n" + "="*80)
            print("SAMPLE SERVICE CREATION".center(80))
            print("="*80)
            print("\nCreate a service file:")
            print(f"{Color.CYAN}mkdir -p ~/.config/systemd/user{Color.RESET}")
            print(f"{Color.CYAN}cat > ~/.config/systemd/user/sample.service << 'EOF'{Color.RESET}")
            print("""[Unit]
Description=Sample Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/sleep infinity
Restart=always
RestartSec=10
Environment=MY_VAR=value

[Install]
WantedBy=default.target
EOF""")
            print(f"\n{Color.CYAN}systemctl --user daemon-reload{Color.RESET}")
            print(f"{Color.CYAN}systemctl --user enable --now sample.service{Color.RESET}")
            print(f"{Color.CYAN}systemctl --user status sample.service{Color.RESET}")
        
        if args.json:
            checker.export_json(args.output)
        
        print_help_commands()
        
        if results['summary'] and results['summary'].get('manager', {}).get('running'):
            sys.exit(ExitCode.SUCCESS.value)
        else:
            sys.exit(ExitCode.MANAGER_NOT_RUNNING.value)
            
    except KeyboardInterrupt:
        print(f"\n{Color.YELLOW}Interrupted by user{Color.RESET}")
        sys.exit(ExitCode.INTERRUPTED.value)
    except PermissionError as e:
        print(f"{Color.RED}Permission Error: {e}{Color.RESET}", file=sys.stderr)
        sys.exit(ExitCode.PERMISSION_ERROR.value)
    except Exception as e:
        print(f"{Color.RED}Error: {e}{Color.RESET}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(ExitCode.ENVIRONMENT_ERROR.value)


if __name__ == "__main__":
    main()
