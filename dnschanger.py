import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import platform
import re
import json
from pathlib import Path

class DNSChanger:
    def __init__(self, root):
        self.root = root
        self.root.title("DNS Changer")
        self.root.geometry("600x400")
        
        # Store common DNS providers
        self.dns_providers = {
            "Google DNS": ["8.8.8.8", "8.8.4.4"],
            "Cloudflare": ["1.1.1.1", "1.0.0.1"],
            "OpenDNS": ["208.67.222.222", "208.67.220.220"],
            "Custom": ["", ""]
        }
        
        self.create_widgets()
        self.load_current_dns()
        
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # DNS Provider selection
        ttk.Label(main_frame, text="Select DNS Provider:").grid(row=0, column=0, pady=5, sticky=tk.W)
        self.provider_var = tk.StringVar()
        self.provider_combo = ttk.Combobox(main_frame, textvariable=self.provider_var)
        self.provider_combo['values'] = list(self.dns_providers.keys())
        self.provider_combo.grid(row=0, column=1, pady=5, sticky=tk.W)
        self.provider_combo.bind('<<ComboboxSelected>>', self.on_provider_select)
        
        # Primary DNS
        ttk.Label(main_frame, text="Primary DNS:").grid(row=1, column=0, pady=5, sticky=tk.W)
        self.primary_dns = ttk.Entry(main_frame, width=20)
        self.primary_dns.grid(row=1, column=1, pady=5, sticky=tk.W)
        
        # Secondary DNS
        ttk.Label(main_frame, text="Secondary DNS:").grid(row=2, column=0, pady=5, sticky=tk.W)
        self.secondary_dns = ttk.Entry(main_frame, width=20)
        self.secondary_dns.grid(row=2, column=1, pady=5, sticky=tk.W)
        
        # Network Interface selection
        ttk.Label(main_frame, text="Network Interface:").grid(row=3, column=0, pady=5, sticky=tk.W)
        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(main_frame, textvariable=self.interface_var)
        self.get_network_interfaces()
        self.interface_combo.grid(row=3, column=1, pady=5, sticky=tk.W)
        
        # Current DNS display
        ttk.Label(main_frame, text="Current DNS:").grid(row=4, column=0, pady=5, sticky=tk.W)
        self.current_dns_label = ttk.Label(main_frame, text="")
        self.current_dns_label.grid(row=4, column=1, pady=5, sticky=tk.W)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=5, column=0, columnspan=2, pady=20)
        
        ttk.Button(button_frame, text="Apply DNS", command=self.apply_dns).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Reset to DHCP", command=self.reset_dns).pack(side=tk.LEFT, padx=5)
        
    def get_network_interfaces(self):
        """Get list of network interfaces based on OS"""
        interfaces = []
        if platform.system() == "Windows":
            try:
                output = subprocess.check_output("ipconfig /all", shell=True).decode()
                # Extract adapter names using regex
                interfaces = re.findall(r"adapter (.+?):", output)
            except subprocess.CalledProcessError:
                messagebox.showerror("Error", "Failed to get network interfaces")
        else:  # Linux/MacOS
            try:
                output = subprocess.check_output("ifconfig", shell=True).decode()
                interfaces = re.findall(r"^(\w+):", output, re.MULTILINE)
            except subprocess.CalledProcessError:
                try:
                    # Alternative for some Linux systems
                    output = subprocess.check_output("ip link show", shell=True).decode()
                    interfaces = re.findall(r"^\d+: (\w+):", output, re.MULTILINE)
                except subprocess.CalledProcessError:
                    messagebox.showerror("Error", "Failed to get network interfaces")
        
        self.interface_combo['values'] = interfaces
        if interfaces:
            self.interface_combo.set(interfaces[0])
    
    def load_current_dns(self):
        """Load and display current DNS settings"""
        interface = self.interface_var.get()
        if not interface:
            return
            
        try:
            if platform.system() == "Windows":
                output = subprocess.check_output(f"ipconfig /all", shell=True).decode()
                # Find DNS servers for selected interface
                interface_section = output[output.find(interface):]
                dns_servers = re.findall(r"DNS Servers[^:]*:\s*([^\s]+)", interface_section)
            else:  # Linux/MacOS
                output = subprocess.check_output(f"cat /etc/resolv.conf", shell=True).decode()
                dns_servers = re.findall(r"nameserver\s+([^\s]+)", output)
            
            if dns_servers:
                self.current_dns_label.config(text=", ".join(dns_servers))
        except subprocess.CalledProcessError:
            self.current_dns_label.config(text="Unable to fetch current DNS")
    
    def on_provider_select(self, event=None):
        """Update DNS entries when provider is selected"""
        provider = self.provider_var.get()
        if provider in self.dns_providers:
            self.primary_dns.delete(0, tk.END)
            self.secondary_dns.delete(0, tk.END)
            self.primary_dns.insert(0, self.dns_providers[provider][0])
            self.secondary_dns.insert(0, self.dns_providers[provider][1])
    
    def validate_ip(self, ip):
        """Validate IP address format"""
        try:
            parts = ip.split('.')
            return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
        except (AttributeError, TypeError, ValueError):
            return False
    
    def apply_dns(self):
        """Apply the DNS settings"""
        primary = self.primary_dns.get()
        secondary = self.secondary_dns.get()
        interface = self.interface_var.get()
        
        if not all([primary, secondary, interface]):
            messagebox.showerror("Error", "Please fill in all fields")
            return
        
        if not all([self.validate_ip(primary), self.validate_ip(secondary)]):
            messagebox.showerror("Error", "Invalid IP address format")
            return
        
        try:
            if platform.system() == "Windows":
                # Using netsh for Windows
                subprocess.run([
                    'netsh', 'interface', 'ip', 'set', 'dns',
                    interface, 'static', primary
                ], check=True)
                subprocess.run([
                    'netsh', 'interface', 'ip', 'add', 'dns',
                    interface, secondary, 'index=2'
                ], check=True)
            else:
                # For Linux/MacOS, modify resolv.conf
                with open('/etc/resolv.conf', 'w') as f:
                    f.write(f"nameserver {primary}\n")
                    f.write(f"nameserver {secondary}\n")
            
            messagebox.showinfo("Success", "DNS settings applied successfully")
            self.load_current_dns()
        except subprocess.CalledProcessError:
            messagebox.showerror("Error", "Failed to apply DNS settings. Make sure you have administrative privileges.")
        except PermissionError:
            messagebox.showerror("Error", "Permission denied. Run the application as administrator.")
    
    def reset_dns(self):
        """Reset DNS to DHCP"""
        interface = self.interface_var.get()
        
        try:
            if platform.system() == "Windows":
                subprocess.run([
                    'netsh', 'interface', 'ip', 'set', 'dns',
                    interface, 'dhcp'
                ], check=True)
            else:
                # For Linux/MacOS, typically managed by NetworkManager or similar
                if platform.system() == "Linux":
                    subprocess.run(['sudo', 'dhclient', '-r'], check=True)
                    subprocess.run(['sudo', 'dhclient'], check=True)
                else:  # MacOS
                    subprocess.run(['sudo', 'networksetup', '-setdnsservers', interface, "Empty"], check=True)
            
            messagebox.showinfo("Success", "DNS reset to DHCP successfully")
            self.load_current_dns()
        except subprocess.CalledProcessError:
            messagebox.showerror("Error", "Failed to reset DNS settings. Make sure you have administrative privileges.")
        except PermissionError:
            messagebox.showerror("Error", "Permission denied. Run the application as administrator.")

if __name__ == "__main__":
    root = tk.Tk()
    app = DNSChanger(root)
    root.mainloop()