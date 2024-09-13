import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import time
from scapy.all import sniff, IP, TCP, UDP, ARP, ICMP, Ether, get_if_list
import json
from collections import Counter

class AdvancedSnifferGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Advanced Network Sniffer")
        self.master.geometry("1200x800")
        self.master.configure(bg='#2b2b2b')

        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure("TFrame", background='#2b2b2b')
        self.style.configure("TLabel", background='#2b2b2b', foreground='#ffffff')
        self.style.configure("TButton", background='#3c3f41', foreground='#ffffff')
        self.style.map('TButton', background=[('active', '#4c4f51')])

        self.create_widgets()

        self.sniffer_thread = None
        self.running = False
        self.packets = []
        self.stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "Other": 0}
        self.port_counter = Counter()
        self.ip_counter = Counter()




    def create_widgets(self):
        main_frame = ttk.Frame(self.master)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        interface_frame = ttk.Frame(main_frame)
        interface_frame.pack(fill=tk.X, pady=5)
        ttk.Label(interface_frame, text="Interface:").pack(side=tk.LEFT)
        self.interface_combo = ttk.Combobox(interface_frame, values=get_if_list(), style="TCombobox")
        self.interface_combo.pack(side=tk.LEFT, padx=5)
        if get_if_list():
            self.interface_combo.set(get_if_list()[0])

        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=5)
        self.start_button = ttk.Button(control_frame, text="Start", command=self.start_sniffing)
        self.start_button.pack(side=tk.LEFT, padx=5)
        self.stop_button = ttk.Button(control_frame, text="Stop", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        self.save_button = ttk.Button(control_frame, text="Save Log", command=self.save_log)
        self.save_button.pack(side=tk.LEFT, padx=5)

        filter_frame = ttk.Frame(main_frame)
        filter_frame.pack(fill=tk.X, pady=5)
        ttk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT)
        self.filter_entry = ttk.Entry(filter_frame, width=30)
        self.filter_entry.pack(side=tk.LEFT, padx=5)
        ttk.Button(filter_frame, text="Apply", command=self.apply_filter).pack(side=tk.LEFT)

        self.packet_display = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, bg='#1e1e1e', fg='#ffffff')
        self.packet_display.pack(expand=True, fill=tk.BOTH, pady=5)

        self.stats_frame = ttk.Frame(main_frame)
        self.stats_frame.pack(fill=tk.X, pady=5)
        self.stats_label = ttk.Label(self.stats_frame, text="TCP: 0 | UDP: 0 | ICMP: 0 | ARP: 0 | Other: 0")
        self.stats_label.pack(side=tk.LEFT, padx=(0, 20))
        self.port_stats_label = ttk.Label(self.stats_frame, text="Top Ports: ")
        self.port_stats_label.pack(side=tk.LEFT, padx=(0, 20))
        self.ip_stats_label = ttk.Label(self.stats_frame, text="Top IPs: ")
        self.ip_stats_label.pack(side=tk.LEFT)

    def start_sniffing(self):
        interface = self.interface_combo.get()
        if not interface:
            messagebox.showerror("Error", "Please select an interface")
            return

        self.running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.sniffer_thread = threading.Thread(target=self.sniff_packets, args=(interface,))
        self.sniffer_thread.start()

    def stop_sniffing(self):
        self.running = False
        if self.sniffer_thread:
            self.sniffer_thread.join(timeout=2)
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def sniff_packets(self, interface):
        try:
            sniff(iface=interface, prn=self.process_packet, store=False, stop_filter=lambda _: not self.running)
        except Exception as e:
            self.master.after(0, lambda: messagebox.showerror("Error", f"Sniffing error: {str(e)}"))
            self.master.after(0, self.stop_sniffing)

    def process_packet(self, packet):
        packet_info = {
            "time": time.strftime('%Y-%m-%d %H:%M:%S'),
            "length": len(packet)
        }

        if Ether in packet:
            packet_info["src_mac"] = packet[Ether].src
            packet_info["dst_mac"] = packet[Ether].dst

        if IP in packet:
            packet_info["src_ip"] = packet[IP].src
            packet_info["dst_ip"] = packet[IP].dst
            packet_info["proto"] = packet[IP].proto
            self.ip_counter[packet[IP].src] += 1
            self.ip_counter[packet[IP].dst] += 1

            if TCP in packet:
                packet_info["src_port"] = packet[TCP].sport
                packet_info["dst_port"] = packet[TCP].dport
                packet_info["proto_name"] = "TCP"
                packet_info["flags"] = packet[TCP].flags
                self.stats["TCP"] += 1
                self.port_counter[packet[TCP].sport] += 1
                self.port_counter[packet[TCP].dport] += 1
            elif UDP in packet:
                packet_info["src_port"] = packet[UDP].sport
                packet_info["dst_port"] = packet[UDP].dport
                packet_info["proto_name"] = "UDP"
                self.stats["UDP"] += 1
                self.port_counter[packet[UDP].sport] += 1
                self.port_counter[packet[UDP].dport] += 1
            elif ICMP in packet:
                packet_info["proto_name"] = "ICMP"
                packet_info["icmp_type"] = packet[ICMP].type
                packet_info["icmp_code"] = packet[ICMP].code
                self.stats["ICMP"] += 1
            else:
                packet_info["proto_name"] = "Other IP"
                self.stats["Other"] += 1
        elif ARP in packet:
            packet_info["proto_name"] = "ARP"
            packet_info["src_ip"] = packet[ARP].psrc
            packet_info["dst_ip"] = packet[ARP].pdst
            self.stats["ARP"] += 1
        else:
            packet_info["proto_name"] = "Unknown"
            self.stats["Other"] += 1

        self.packets.append(packet_info)
        self.master.after(0, self.update_display)

    def update_display(self):
        self.packet_display.delete(1.0, tk.END)
        for packet in self.packets[-100:]:
            packet_text = f"{packet['time']} - {packet['proto_name']} - "
            if 'src_ip' in packet:
                packet_text += f"{packet['src_ip']}"
                if 'src_port' in packet:
                    packet_text += f":{packet['src_port']}"
                packet_text += " -> "
                packet_text += f"{packet['dst_ip']}"
                if 'dst_port' in packet:
                    packet_text += f":{packet['dst_port']}"
            if 'flags' in packet:
                packet_text += f" Flags: {packet['flags']}"
            if 'icmp_type' in packet:
                packet_text += f" Type: {packet['icmp_type']} Code: {packet['icmp_code']}"
            packet_text += f" Length: {packet['length']}\n"
            self.packet_display.insert(tk.END, packet_text)
        self.packet_display.see(tk.END)
        self.update_stats()

    def update_stats(self):
        stats_text = f"TCP: {self.stats['TCP']} | UDP: {self.stats['UDP']} | ICMP: {self.stats['ICMP']} | ARP: {self.stats['ARP']} | Other: {self.stats['Other']}"
        self.stats_label.config(text=stats_text)

        top_ports = self.port_counter.most_common(4)
        port_stats_text = "Top Ports: " + " | ".join(f"{port}: {count}" for port, count in top_ports)
        self.port_stats_label.config(text=port_stats_text)

        top_ips = self.ip_counter.most_common(4)
        ip_stats_text = "Top IPs: " + " | ".join(f"{ip}: {count}" for ip, count in top_ips)
        self.ip_stats_label.config(text=ip_stats_text)

    def apply_filter(self):
        filter_text = self.filter_entry.get().lower()
        self.packet_display.delete(1.0, tk.END)
        for packet in self.packets:
            if (filter_text in str(packet).lower()):
                packet_text = f"{packet['time']} - {packet['proto_name']} - "
                if 'src_ip' in packet:
                    packet_text += f"{packet['src_ip']}"
                    if 'src_port' in packet:
                        packet_text += f":{packet['src_port']}"
                    packet_text += " -> "
                    packet_text += f"{packet['dst_ip']}"
                    if 'dst_port' in packet:
                        packet_text += f":{packet['dst_port']}"
                if 'flags' in packet:
                    packet_text += f" Flags: {packet['flags']}"
                if 'icmp_type' in packet:
                    packet_text += f" Type: {packet['icmp_type']} Code: {packet['icmp_code']}"
                packet_text += f" Length: {packet['length']}\n"
                self.packet_display.insert(tk.END, packet_text)
        self.packet_display.see(tk.END)

    def save_log(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".json",
                                                 filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if file_path:
            with open(file_path, 'w') as f:
                json.dump(self.packets, f, indent=2)
            messagebox.showinfo("Info", "Log saved successfully")

if __name__ == '__main__':
    root = tk.Tk()
    app = AdvancedSnifferGUI(root)
    root.mainloop()
