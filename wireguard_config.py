import tkinter as tk
from tkinter import messagebox, filedialog, ttk
import subprocess

class WireGuardConfig:
    def __init__(self, master):
        self.master = master
        self.wireguard_window = None

    def open_config_window(self):
        """Open a new window for configuring WireGuard settings."""
        self.wireguard_window = tk.Toplevel(self.master)
        self.wireguard_window.title("WireGuard Configuration")

        # WireGuard server configuration fields
        tk.Label(self.wireguard_window, text="WireGuard Server Configuration").pack(pady=10)

        tk.Label(self.wireguard_window, text="Private Key (Server):").pack(pady=5)
        self.private_key_entry = tk.Entry(self.wireguard_window, width=100, font=("Arial", 12))
        self.private_key_entry.pack(pady=5)

        tk.Label(self.wireguard_window, text="Server IP Address / Subnet (e.g., 10.0.0.1/24):").pack(pady=5)
        self.server_ip_entry = tk.Entry(self.wireguard_window, width=50)
        self.server_ip_entry.pack(pady=5)

        tk.Label(self.wireguard_window, text="Listening Port:").pack(pady=5)
        self.listen_port_entry = tk.Entry(self.wireguard_window)
        self.listen_port_entry.pack(pady=5)

        tk.Label(self.wireguard_window, text="Public Interface (e.g., ens160):").pack(pady=5)
        self.public_interface_entry = tk.Entry(self.wireguard_window)
        self.public_interface_entry.pack(pady=5)

        # Client configuration fields
        tk.Label(self.wireguard_window, text="Client Configuration").pack(pady=20)

        tk.Label(self.wireguard_window, text="Client Public Key:").pack(pady=5)
        self.client_public_key_entry = tk.Entry(self.wireguard_window, width=100, font=("Arial", 12))
        self.client_public_key_entry.pack(pady=5)

        tk.Label(self.wireguard_window, text="Client Allowed IPs (e.g., 10.0.0.2/32):").pack(pady=5)
        self.client_allowed_ips_entry = tk.Entry(self.wireguard_window)
        self.client_allowed_ips_entry.pack(pady=5)

        # Dropdown for selecting WireGuard interface
        tk.Label(self.wireguard_window, text="Select Interface:").pack(pady=5)
        self.interface_combobox = ttk.Combobox(self.wireguard_window, values=["wg0", "wg1", "wg2"])  # Add more interfaces as needed
        self.interface_combobox.pack(pady=5)

        # Buttons to save and manage WireGuard configuration
        self.save_button = tk.Button(self.wireguard_window, text="Save Configuration", command=self.save_wireguard_config)
        self.save_button.pack(pady=5)

        self.start_button = tk.Button(self.wireguard_window, text="Start WireGuard", command=self.start_wireguard)
        self.start_button.pack(pady=5)

        self.stop_button = tk.Button(self.wireguard_window, text="Stop WireGuard", command=self.stop_wireguard)
        self.stop_button.pack(pady=5)

    def save_wireguard_config(self):
        """Save WireGuard configuration to a file."""
        # Server configuration details
        private_key = self.private_key_entry.get()
        server_ip = self.server_ip_entry.get()
        listen_port = self.listen_port_entry.get()
        public_interface = self.public_interface_entry.get()

        # Client configuration details
        client_public_key = self.client_public_key_entry.get()
        client_allowed_ips = self.client_allowed_ips_entry.get()

        # Validate inputs
        if not private_key or not server_ip or not listen_port or not public_interface or not client_public_key or not client_allowed_ips:
            messagebox.showwarning("Warning", "All fields must be filled out.")
            return

        # WireGuard server configuration content
        config_content = (
            "[Interface]\n"
            f"PrivateKey = {private_key}\n"
            f"Address = {server_ip}\n"
            "SaveConfig = true\n"
            f"ListenPort = {listen_port}\n"
            f"PostUp = iptables -A FORWARD -i {self.interface_combobox.get()} -j ACCEPT; iptables -t nat -A POSTROUTING -o {public_interface} -j MASQUERADE;\n"
            f"PostDown = iptables -D FORWARD -i {self.interface_combobox.get()} -j ACCEPT; iptables -t nat -D POSTROUTING -o {public_interface} -j MASQUERADE;\n"
            "\n"
            "[Peer]\n"
            f"PublicKey = {client_public_key}\n"
            f"AllowedIPs = {client_allowed_ips}\n"
        )

        file_path = filedialog.asksaveasfilename(defaultextension=".conf", filetypes=[("WireGuard Config", "*.conf")])
        if file_path:
            with open(file_path, 'w') as file:
                file.write(config_content)
            messagebox.showinfo("Success", "WireGuard configuration saved successfully!")

    def start_wireguard(self):
        """Start WireGuard using wg-quick."""
        config_file = filedialog.askopenfilename(filetypes=[("WireGuard Config", "*.conf")])
        interface = self.interface_combobox.get()

        if config_file and interface:
            try:
                subprocess.run(['wg-quick', 'up', interface], check=True)
                messagebox.showinfo("Success", "WireGuard started successfully!")
            except subprocess.CalledProcessError:
                messagebox.showerror("Error", "Failed to start WireGuard.")

    def stop_wireguard(self):
        """Stop WireGuard using wg-quick."""
        interface = self.interface_combobox.get()

        if interface:
            try:
                subprocess.run(['wg-quick', 'down', interface], check=True)
                messagebox.showinfo("Success", "WireGuard stopped successfully!")
            except subprocess.CalledProcessError:
                messagebox.showerror("Error", "Failed to stop WireGuard.")

if __name__ == "__main__":
    root = tk.Tk()
    app = WireGuardConfig(root)
    app.open_config_window()
    root.mainloop()
