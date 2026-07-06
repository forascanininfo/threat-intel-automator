import subprocess
import platform
import sys

def block_ip_address(ip_address):
    current_os = platform.system().lower()
    if current_os =="windows":
        rule_name =f"Block_Threat_Intel_{ip_address}"
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=in",
            "action=block",
            f"remoteip={ip_address}"
        ]
    elif current_os =="linux":
        cmd =[
            "iptables", "-A", "INPUT",
            "-s", ip_address,
            "-j", "DROP"
        ]
    else:
        print(f"[FIREWALL] Unsupported operating system: {platform.system()}")
        return False

    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr= subprocess.PIPE, text=True)
        if result.returncode == 0:
            print(f"[FIREWALL] IP address {ip_address} has been successfully BLOCKED!")
            return True
        else:
            error_message = result.stderr.strip() if result.stderr.strip() else result.stdout.strip()
            
            if current_os == "linux" and "permission denied" in error_message.lower():
                error_message = "Requires root privilegies. Run the script with 'sudo'."
            print(f"[FIREWALL] Failed to block {ip_address}. System Message: {error_message}")
            return False
    except Exception as e:
        print(f"Error executing firewall command: {e}")
        return False