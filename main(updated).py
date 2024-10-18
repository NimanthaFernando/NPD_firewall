import subprocess
import tkinter as tk
from tkinter import messagebox, ttk, filedialog
from pyroute2 import IPRoute
import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
from wireguard_config import WireGuardConfig


class SimpleFirewall:
    def __init__(self, master):
        self.master = master
        self.master.title("Simple Firewall")

        # Create a frame for controls
        self.control_frame = tk.Frame(master)
        self.control_frame.pack(side=tk.LEFT, padx=10, pady=10)

        # Create input fields for source and destination IP
        self.source_label = tk.Label(self.control_frame, text="Source IP:")
        self.source_label.pack(pady=5)
        self.source_entry = tk.Entry(self.control_frame)
        self.source_entry.pack(pady=5)

        self.destination_label = tk.Label(self.control_frame, text="Destination IP:")
        self.destination_label.pack(pady=5)
        self.destination_entry = tk.Entry(self.control_frame)
        self.destination_entry.pack(pady=5)

        # Create dropdown for interface selection
        self.interface_label = tk.Label(self.control_frame, text="Network Interface:")
        self.interface_label.pack(pady=5)
        self.interface_var = tk.StringVar()
        self.interface_dropdown = ttk.Combobox(self.control_frame, textvariable=self.interface_var)
        self.interface_dropdown['values'] = self.get_interfaces()
        self.interface_dropdown.pack(pady=5)

        self.protocol_label = tk.Label(self.control_frame, text="Protocol (tcp/udp/icmp):")
        self.protocol_label.pack(pady=5)
        self.protocol_entry = tk.Entry(self.control_frame)
        self.protocol_entry.pack(pady=5)

        self.port_label = tk.Label(self.control_frame, text="Port (Leave blank for all):")
        self.port_label.pack(pady=5)
        self.port_entry = tk.Entry(self.control_frame)
        self.port_entry.pack(pady=5)

        # Firewall control buttons
        self.apply_button = tk.Button(self.control_frame, text="Apply Rule", command=self.apply_rule)
        self.apply_button.pack(pady=5)

        self.remove_button = tk.Button(self.control_frame, text="Remove Selected Rule", command=self.remove_selected_rule)
        self.remove_button.pack(pady=5)

        # Routing control buttons
        self.add_route_button = tk.Button(self.control_frame, text="Add Routes", command=self.add_routes)
        self.add_route_button.pack(pady=5)

        self.remove_route_button = tk.Button(self.control_frame, text="Remove Routes", command=self.remove_routes)
        self.remove_route_button.pack(pady=5)

        # Button for generating log report
        self.report_button = tk.Button(self.control_frame, text="Generate Log Report", command=self.generate_log_report)
        self.report_button.pack(pady=5)

        # New button for saving log counts
        self.save_log_counts_button = tk.Button(self.control_frame, text="Save Log Counts", command=self.save_log_counts)
        self.save_log_counts_button.pack(pady=5)

        # Create an instance of WireGuardConfig
        self.wireguard_config = WireGuardConfig(self.master)
        # Button for configuring WireGuard
        self.wireguard_button = tk.Button(self.control_frame, text="Configure WireGuard", command=self.wireguard_config.open_config_window)
        self.wireguard_button.pack(pady=5)

        # Create a frame for the rules display
        self.rules_frame = tk.Frame(master)
        self.rules_frame.pack(side=tk.TOP, padx=10, pady=10)

        # Listbox for displaying current firewall rules
        self.rules_label = tk.Label(self.rules_frame, text="Current Firewall Rules:")
        self.rules_label.pack(pady=5)

        self.rules_listbox = tk.Listbox(self.rules_frame, width=50, height=10)
        self.rules_listbox.pack(pady=5)

        # Log area
        self.log_frame = tk.Frame(master)
        self.log_frame.pack(side=tk.RIGHT, padx=10, pady=10)

        self.log_label = tk.Label(self.log_frame, text="Firewall Log:")
        self.log_label.pack(pady=5)

        self.log_text = tk.Text(self.log_frame, height=40, width=120)
        self.log_text.pack(pady=5)

        # Status label
        self.status_label = tk.Label(master, text="")
        self.status_label.pack(pady=10)

        # Start packet inspection in a separate thread
        self.packet_thread = threading.Thread(target=self.start_packet_inspection, daemon=True)
        self.packet_thread.start()

        # Load current rules into the Listbox
        self.load_current_rules()

    def get_interfaces(self):
        """Get a list of network interfaces."""
        try:
            result = subprocess.run(["ip", "link", "show"], capture_output=True, text=True, check=True)
            interfaces = []
            for line in result.stdout.splitlines():
                if ":" in line:
                    interface_name = line.split(":")[1].strip()
                    interfaces.append(interface_name)
            return interfaces
        except subprocess.CalledProcessError:
            messagebox.showerror("Error", "Failed to retrieve network interfaces.")
            return []

    def apply_rule(self):
        """Apply a new firewall rule and update the Listbox."""
        source = self.source_entry.get()
        destination = self.destination_entry.get()
        protocol = self.protocol_entry.get().lower() or None
        port = self.port_entry.get() or None
        interface = self.interface_var.get()

        command = ["sudo", "iptables", "-A", "FORWARD", "-i", interface, "-s", source, "-d", destination]

        if protocol:
            command.extend(["-p", protocol])
        if port:
            command.extend(["--dport", str(port)])

        command.extend(["-j", "DROP"])

        try:
            subprocess.run(command, check=True)
            self.status_label.config(text="Rule applied successfully.")
            self.load_current_rules()  # Refresh the Listbox after applying the rule
        except subprocess.CalledProcessError:
            messagebox.showerror("Error", "Failed to apply the rule.")

    def remove_selected_rule(self):
        """Remove the selected rule from the Listbox using its line number."""
        selected_rule_index = self.rules_listbox.curselection()

        if selected_rule_index:
            selected_rule = self.rules_listbox.get(selected_rule_index)

            # Extract the line number from the selected rule in the Listbox
            parts = selected_rule.split(" | ")
            if len(parts) < 5:
                messagebox.showerror("Error", "Invalid rule selected.")
                return

            # Get the line number from the selected rule
            rule_num = parts[0]

            try:
                # Use iptables -D with the line number to delete the rule
                subprocess.run(
                    ["sudo", "iptables", "-D", "FORWARD", rule_num],
                    check=True
                )
                self.status_label.config(text="Selected rule removed successfully.")
                self.load_current_rules()  # Refresh the Listbox after removing the rule
            except subprocess.CalledProcessError:
                messagebox.showerror("Error", "Failed to remove the rule.")
        else:
            messagebox.showwarning("Warning", "No rule selected.")

    def load_current_rules(self):
        """Load current firewall rules into the Listbox."""
        self.rules_listbox.delete(0, tk.END)  # Clear existing rules

        try:
            result = subprocess.run(
                ["sudo", "iptables", "-L", "FORWARD", "-n", "--line-numbers"],
                capture_output=True,
                text=True,
                check=True
            )
            lines = result.stdout.splitlines()
            for line in lines[2:]:  # Skip the first two lines (headers)
                parts = line.split()
                if len(parts) < 6:  # Ensure there are enough parts for a valid rule
                    continue
                rule_num = parts[0]  # Line number
                source = parts[3]
                destination = parts[4]
                target = parts[1]  # DROP, ACCEPT, etc.
                interface = parts[-1]  # Interface is usually at the end

                # Format: LineNumber | Source | Destination | Target | Interface
                rule_description = f"{rule_num} | {source} | {destination} | {target} | {interface}"
                self.rules_listbox.insert(tk.END, rule_description)
        except subprocess.CalledProcessError:
            messagebox.showerror("Error", "Failed to retrieve current firewall rules.")

    def add_routes(self):
        """Add network routes."""
        ingress_iface = "ens192"  # Example interface names
        egress_iface = "ens160"
        ingress_network = "192.168.3.0/24"
        egress_network = "172.168.3.0/24"

        try:
            ip = IPRoute()
            ingress_idx = ip.link_lookup(ifname=ingress_iface)
            egress_idx = ip.link_lookup(ifname=egress_iface)

            if not ingress_idx or not egress_idx:
                messagebox.showerror("Error", "Interfaces not found!")
                return

            ip.route('add', dst=egress_network, gateway='172.168.3.34', oif=egress_idx[0])
            ip.route('add', dst=ingress_network, gateway='192.168.3.34', oif=ingress_idx[0])

            ip.close()
            self.status_label.config(text="Routes added between VM 1 and VM 2.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to add routes: {str(e)}")

    def remove_routes(self):
        """Remove network routes."""
        ingress_iface = "ens192"  # Example interface names
        egress_iface = "ens160"
        ingress_network = "192.168.3.0/24"
        egress_network = "172.168.3.0/24"

        try:
            ip = IPRoute()
            ingress_idx = ip.link_lookup(ifname=ingress_iface)
            egress_idx = ip.link_lookup(ifname=egress_iface)

            if not ingress_idx or not egress_idx:
                messagebox.showerror("Error", "Interfaces not found!")
                return

            ip.route('delete', dst=egress_network, gateway='172.168.3.34', oif=egress_idx[0])
            ip.route('delete', dst=ingress_network, gateway='192.168.3.34', oif=ingress_idx[0])

            ip.close()
            self.status_label.config(text="Routes removed between VM 1 and VM 2.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to remove routes: {str(e)}")

    def _categorize_log_content(self, log_content):
        """Categorize log content into sections based on packet type."""
        categorized_log = {
            "ICMP": [],
            "TCP": [],
            "UDP": [],
            "Other": []
        }

        # Split the log into lines and categorize based on packet type
        log_lines = log_content.splitlines()
        for line in log_lines:
            if "ICMP" in line:
                categorized_log["ICMP"].append(line)
            elif "TCP" in line:
                categorized_log["TCP"].append(line)
            elif "UDP" in line:
                categorized_log["UDP"].append(line)
            else:
                categorized_log["Other"].append(line)

        # Build the final categorized log content
        categorized_log_content = ""

        for category, lines in categorized_log.items():
            if lines:
                categorized_log_content += f"\n--- {category} Packets ---\n"
                categorized_log_content += "\n".join(lines) + "\n"

        return categorized_log_content

    def generate_log_report(self):
        """Generate a log report and save it to a file."""
        log_content = self.log_text.get("1.0", tk.END)  # Get all text from the log area

        if not log_content.strip():  # Check if log is empty
            messagebox.showwarning("Warning", "Log is empty. Nothing to save.")
            return

        # Categorize log messages into sections
        categorized_log = self._categorize_log_content(log_content)

        # Prompt the user for a file location
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Save Log Report"
        )

        if file_path:  # If user didn't cancel the dialog
            with open(file_path, 'w') as log_file:
                log_file.write(categorized_log)  # Write categorized log content to the file
            messagebox.showinfo("Success", "Log report generated successfully.")

    def save_log_counts(self):
        """Generate a report of logs categorized by date and type."""
        logs = self.log_text.get("1.0", tk.END).strip().splitlines()

        log_counts = {
            'INFO': 0,
            'WARN': 0,
            'ERROR': 0
        }

        report_by_date = {}
        for log in logs:
            # Example log format: 2024-10-12 15:00:03 INFO Rule applied
            try:
                log_date, log_time, log_type, *log_message = log.split(" ", 3)
                date = log_date
                log_counts[log_type] += 1

                if date not in report_by_date:
                    report_by_date[date] = {'INFO': 0, 'WARN': 0, 'ERROR': 0}
                report_by_date[date][log_type] += 1
            except ValueError:
                continue  # Skip if the log is not formatted as expected

        # Prepare report
        report = "Log Report\n\n"
        report += "Summary by Date:\n"
        for date, counts in report_by_date.items():
            report += f"{date}: INFO={counts['INFO']}, WARN={counts['WARN']}, ERROR={counts['ERROR']}\n"

        report += "\nTotal Log Counts:\n"
        report += f"INFO: {log_counts['INFO']}\n"
        report += f"WARN: {log_counts['WARN']}\n"
        report += f"ERROR: {log_counts['ERROR']}\n"

        # Ask user for file save location
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, 'w') as f:
                f.write(report)

            messagebox.showinfo("Log Report", f"Log report saved to {file_path}")
    def start_packet_inspection(self):
        """Start inspecting packets using Scapy."""
        sniff(prn=self.inspect_packet, store=False)

    def inspect_packet(self, packet):
        """Inspect a packet and log details."""
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "ICMP" if ICMP in packet else "OTHER"

            log_message = f"{datetime.now()} INFO {protocol} packet: {src_ip} -> {dst_ip}\n"
            self.log_text.insert(tk.END, log_message)
            self.log_text.see(tk.END)  # Auto-scroll to the latest log


if __name__ == "__main__":
    root = tk.Tk()
    app = SimpleFirewall(root)
    root.mainloop()
