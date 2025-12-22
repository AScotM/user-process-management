#!/usr/bin/env python3
import subprocess
import json
import sys
import os
import pwd
import grp
from tabulate import tabulate

class SystemdUserProcessChecker:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.user_info = {}
    
    def run_command(self, cmd, user_mode=False):
        try:
            if user_mode:
                cmd = f"sudo -u {os.getlogin()} {cmd}"
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                check=False
            )
            return result.stdout.strip(), result.returncode
        except Exception:
            return "", 1
    
    def display_table(self, title, headers, data, table_format="simple"):
        print("\n" + "="*80)
        print(title.center(80))
        print("="*80)
        if data:
            print(tabulate(data, headers=headers, tablefmt=table_format))
        else:
            print("No data available")
    
    def check_current_user(self):
        user_data = []
        current_user = os.getlogin()
        user_id = os.getuid()
        
        user_data.append(["Username", current_user])
        user_data.append(["User ID", str(user_id)])
        user_data.append(["Home Directory", os.path.expanduser("~")])
        
        try:
            groups = [g.gr_name for g in grp.getgrall() if current_user in g.gr_mem]
            user_data.append(["Group Memberships", ", ".join(groups[:5]) + ("..." if len(groups) > 5 else "")])
        except:
            user_data.append(["Group Memberships", "Unknown"])
        
        self.display_table(
            "CURRENT USER INFORMATION",
            ["Property", "Value"],
            user_data
        )
        
        self.user_info['current_user'] = {
            'name': current_user,
            'uid': user_id,
            'home': os.path.expanduser("~")
        }
        
        return current_user
    
    def check_user_service_directories(self):
        dir_data = []
        
        user_config_dir = os.path.expanduser("~/.config/systemd/user")
        user_runtime_dir = f"/run/user/{os.getuid()}/systemd"
        user_local_dir = os.path.expanduser("~/.local/share/systemd/user")
        
        directories = [
            ("User Config", user_config_dir),
            ("User Runtime", user_runtime_dir),
            ("User Local", user_local_dir)
        ]
        
        for name, path in directories:
            exists = os.path.exists(path)
            is_dir = os.path.isdir(path) if exists else False
            file_count = 0
            
            if exists and is_dir:
                try:
                    file_count = len([f for f in os.listdir(path) if f.endswith('.service') or f.endswith('.socket') or f.endswith('.timer')])
                except:
                    file_count = -1
            
            status = "Present" if exists else "Missing"
            if file_count > 0:
                status = f"Present ({file_count} units)"
            
            dir_data.append([name, path, status])
        
        self.display_table(
            "USER SYSTEMD DIRECTORIES",
            ["Directory Type", "Path", "Status"],
            dir_data
        )
        
        self.user_info['directories'] = dir_data
        
        return user_config_dir
    
    def check_user_systemd_status(self):
        status_data = []
        
        cmd = "systemctl --user --no-pager"
        output, code = self.run_command(cmd, user_mode=True)
        
        if code == 0:
            lines = output.split('\n')
            for line in lines:
                if "State:" in line:
                    status_data.append(["User Systemd State", line.split("State:", 1)[1].strip()])
                elif "Jobs:" in line:
                    status_data.append(["Active Jobs", line.split("Jobs:", 1)[1].strip()])
                elif "Failed:" in line:
                    status_data.append(["Failed Units", line.split("Failed:", 1)[1].strip()])
        else:
            status_data.append(["User Systemd State", "Not accessible"])
        
        self.display_table(
            "USER SYSTEMD MANAGER STATUS",
            ["Property", "Value"],
            status_data
        )
        
        self.user_info['manager_status'] = status_data
        
        return code == 0
    
    def list_user_services(self):
        cmd = "systemctl --user list-unit-files --type=service --no-pager"
        output, code = self.run_command(cmd, user_mode=True)
        
        service_data = []
        
        if code == 0:
            lines = output.split('\n')
            start_processing = False
            
            for line in lines:
                if "UNIT FILE" in line and "STATE" in line:
                    start_processing = True
                    continue
                
                if start_processing and line.strip() and not line.startswith("unit files listed"):
                    parts = line.split()
                    if len(parts) >= 2:
                        service_name = parts[0]
                        state = parts[-1]
                        service_data.append([service_name, state])
        
        self.display_table(
            "USER SERVICE FILES",
            ["Service Name", "State"],
            service_data[:20]
        )
        
        if len(service_data) > 20:
            print(f"... and {len(service_data) - 20} more services")
        
        self.user_info['services'] = service_data
        
        return service_data
    
    def check_user_sockets(self):
        cmd = "systemctl --user list-units --type=socket --no-pager"
        output, code = self.run_command(cmd, user_mode=True)
        
        socket_data = []
        
        if code == 0:
            lines = output.split('\n')
            start_processing = False
            
            for line in lines:
                if "UNIT" in line and "LOAD" in line and "ACTIVE" in line:
                    start_processing = True
                    continue
                
                if start_processing and line.strip():
                    parts = line.split()
                    if len(parts) >= 4:
                        unit = parts[0]
                        load = parts[1]
                        active = parts[2]
                        socket_data.append([unit, load, active])
        
        self.display_table(
            "USER SOCKET UNITS",
            ["Socket Unit", "Load State", "Active State"],
            socket_data
        )
        
        self.user_info['sockets'] = socket_data
        
        return socket_data
    
    def check_user_timers(self):
        cmd = "systemctl --user list-timers --no-pager"
        output, code = self.run_command(cmd, user_mode=True)
        
        timer_data = []
        
        if code == 0:
            lines = output.split('\n')
            start_processing = False
            
            for line in lines:
                if "NEXT" in line and "LEFT" in line and "LAST" in line:
                    start_processing = True
                    continue
                
                if start_processing and line.strip() and not line.startswith("timers listed"):
                    parts = line.split(maxsplit=5)
                    if len(parts) >= 6:
                        timer_name = parts[0]
                        next_activation = f"{parts[1]} {parts[2]}"
                        time_left = parts[3]
                        last_activation = f"{parts[4]} {parts[5]}" if len(parts) > 5 else parts[4]
                        timer_data.append([timer_name, next_activation, time_left, last_activation])
        
        self.display_table(
            "USER TIMER UNITS",
            ["Timer Name", "Next Activation", "Time Left", "Last Activation"],
            timer_data
        )
        
        self.user_info['timers'] = timer_data
        
        return timer_data
    
    def check_user_service_status(self):
        cmd = "systemctl --user --no-pager"
        output, code = self.run_command(cmd, user_mode=True)
        
        status_data = []
        
        if code == 0:
            lines = output.split('\n')
            for line in lines:
                if "State:" in line:
                    status_data.append(["User Systemd State", line.split("State:", 1)[1].strip()])
                elif "Memory:" in line:
                    status_data.append(["Memory Usage", line.split("Memory:", 1)[1].strip()])
        
        self.display_table(
            "USER SYSTEMD PROCESS STATUS",
            ["Property", "Value"],
            status_data
        )
        
        self.user_info['process_status'] = status_data
        
        return status_data
    
    def check_lingering_users(self):
        cmd = "loginctl list-users --no-pager"
        output, code = self.run_command(cmd)
        
        user_data = []
        
        if code == 0:
            lines = output.split('\n')
            for line in lines:
                if "UID" in line and "USER" in line:
                    continue
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 3:
                        uid = parts[0]
                        user = parts[1]
                        sessions = parts[2]
                        user_data.append([uid, user, sessions])
        
        self.display_table(
            "SYSTEM USERS WITH SESSIONS",
            ["UID", "Username", "Sessions"],
            user_data
        )
        
        self.user_info['system_users'] = user_data
        
        cmd_linger = "loginctl show-user $USER | grep Linger"
        output_linger, _ = self.run_command(cmd_linger, user_mode=True)
        
        linger_status = "Disabled"
        if "Linger=yes" in output_linger:
            linger_status = "Enabled"
        
        linger_data = [[os.getlogin(), linger_status]]
        
        self.display_table(
            "USER LINGER STATUS",
            ["Username", "Linger"],
            linger_data
        )
        
        self.user_info['linger'] = linger_status
        
        return linger_status
    
    def check_user_cgroups(self):
        cmd = "systemd-cgls --user --no-pager"
        output, code = self.run_command(cmd, user_mode=True)
        
        cgroup_data = []
        
        if code == 0:
            lines = output.split('\n')
            service_count = 0
            slice_count = 0
            scope_count = 0
            
            for line in lines:
                if ".service" in line:
                    service_count += 1
                elif ".slice" in line:
                    slice_count += 1
                elif ".scope" in line:
                    scope_count += 1
            
            cgroup_data.append(["Services", str(service_count)])
            cgroup_data.append(["Slices", str(slice_count)])
            cgroup_data.append(["Scopes", str(scope_count)])
        
        self.display_table(
            "USER CGROUP RESOURCES",
            ["Resource Type", "Count"],
            cgroup_data
        )
        
        self.user_info['cgroups'] = cgroup_data
        
        return cgroup_data
    
    def create_sample_user_service(self):
        sample_service = """[Unit]
Description=Sample User Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do echo "User service running at $(date)" >> /tmp/user-service.log; sleep 30; done'
Restart=on-failure

[Install]
WantedBy=default.target
"""
        
        service_path = os.path.expanduser("~/.config/systemd/user/sample-user.service")
        
        service_data = []
        
        if not os.path.exists(os.path.dirname(service_path)):
            service_data.append(["Status", f"Directory {os.path.dirname(service_path)} does not exist"])
        else:
            try:
                with open(service_path, 'w') as f:
                    f.write(sample_service)
                service_data.append(["Status", "Sample service file created"])
                service_data.append(["Path", service_path])
                service_data.append(["Action", "Run: systemctl --user daemon-reload"])
                service_data.append(["Action", "Run: systemctl --user enable --now sample-user.service"])
            except Exception as e:
                service_data.append(["Status", f"Failed to create: {e}"])
        
        self.display_table(
            "SAMPLE USER SERVICE CREATION",
            ["Property", "Value"],
            service_data
        )
        
        return service_data
    
    def generate_summary(self):
        summary_data = []
        
        user_name = self.user_info.get('current_user', {}).get('name', 'Unknown')
        summary_data.append(["Current User", user_name])
        
        services = len(self.user_info.get('services', []))
        summary_data.append(["User Services", str(services)])
        
        sockets = len(self.user_info.get('sockets', []))
        summary_data.append(["User Sockets", str(sockets)])
        
        timers = len(self.user_info.get('timers', []))
        summary_data.append(["User Timers", str(timers)])
        
        linger = self.user_info.get('linger', 'Unknown')
        summary_data.append(["Linger Enabled", linger])
        
        config_exists = any("Present" in str(item) for item in self.user_info.get('directories', []))
        summary_data.append(["Config Directory", "Exists" if config_exists else "Missing"])
        
        manager_ok = any("running" in str(item).lower() for item in self.user_info.get('manager_status', []))
        summary_data.append(["User Manager", "Running" if manager_ok else "Not Running"])
        
        self.display_table(
            "USER PROCESS MANAGEMENT SUMMARY",
            ["Component", "Status"],
            summary_data,
            "grid"
        )
        
        summary = {row[0].lower().replace(" ", "_"): row[1] for row in summary_data}
        self.user_info['summary'] = summary
        return summary
    
    def run_full_check(self):
        print("SYSTEMD USER PROCESS MANAGEMENT ANALYSIS")
        print("="*80)
        
        self.check_current_user()
        self.check_user_service_directories()
        self.check_user_systemd_status()
        self.list_user_services()
        self.check_user_sockets()
        self.check_user_timers()
        self.check_user_service_status()
        self.check_lingering_users()
        self.check_user_cgroups()
        
        if self.verbose:
            self.create_sample_user_service()
        
        summary = self.generate_summary()
        
        return self.user_info, summary
    
    def export_json(self, filename="user_process_mgmt.json"):
        try:
            with open(filename, 'w') as f:
                json.dump(self.user_info, f, indent=2, default=str)
            print(f"User process management state exported to {filename}")
        except Exception as e:
            print(f"Failed to export JSON: {e}")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Check systemd user process management')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output including sample service creation')
    parser.add_argument('--json', '-j', action='store_true', help='Export results to JSON')
    parser.add_argument('--output', '-o', default='user_process_mgmt.json', help='Output JSON filename')
    parser.add_argument('--sample', '-s', action='store_true', help='Create sample user service')
    
    args = parser.parse_args()
    
    checker = SystemdUserProcessChecker(verbose=args.verbose or args.sample)
    user_info, summary = checker.run_full_check()
    
    if args.json:
        checker.export_json(args.output)
    
    print("\nCommon user systemd commands:")
    print("  systemctl --user status                 Check user systemd status")
    print("  systemctl --user start <service>        Start a user service")
    print("  systemctl --user enable <service>       Enable service at login")
    print("  systemctl --user daemon-reload          Reload user unit files")
    print("  journalctl --user                       View user logs")
    print("  loginctl enable-linger                  Enable lingering (run at boot)")
    
    sys.exit(0)


if __name__ == "__main__":
    main()
