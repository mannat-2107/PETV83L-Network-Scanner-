import socket
import ipaddress
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import csv
from queue import Queue
import subprocess
import shutil
import time
import networkx as nx
import matplotlib.pyplot as plt

output_queue = Queue()
PORT_DESCRIPTIONS = {
    21: "FTP",
    22: "Secure Shell (SSH)",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP Web Server",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "Remote Desktop",
    8080: "Alt HTTP",
}

def scan_port(ip, port):
    try:
        s = socket.socket()
        s.settimeout(0.5)
        start_time = time.time()
        s.connect((str(ip), port))
        latency = round((time.time() - start_time) * 1000, 2)

        try:
            banner = s.recv(1024).decode(errors="ignore").strip()
        except:
            banner = "No banner"
        s.close()

        try:
            service = socket.getservbyport(port)
        except:
            service = "Unknown"

        try:
            hostname = socket.gethostbyaddr(str(ip))[0]
        except:
            hostname = "N/A"

        description = PORT_DESCRIPTIONS.get(port, "General Service")

        return (str(ip), hostname, port, service, "TCP", "Open", banner, description, latency)
    except:
        return None

def scan_ip(ip, start_port, end_port, progress_callback):
    total_ports = end_port - start_port + 1
    for i, port in enumerate(range(start_port, end_port + 1), 1):
        result = scan_port(ip, port)
        if result:
            output_queue.put(result)
        progress_callback(i / total_ports)

def update_tree(tree, results):
    try:
        while not output_queue.empty():
            result = output_queue.get_nowait()
            tree.insert("", "end", values=result)
            results.append(result)
    except:
        pass
    finally:
        tree.after(100, update_tree, tree, results)

def start_scan(network, start_port, end_port, tree, results, progress_bar):
    try:
        ip_net = ipaddress.ip_network(network, strict=False)
    except ValueError:
        messagebox.showerror("Invalid CIDR", "Use format like 192.168.1.0/24")
        return

    results.clear()
    for i in tree.get_children():
        tree.delete(i)
    output_queue.queue.clear()

    all_hosts = list(ip_net.hosts())
    total_tasks = len(all_hosts)
    task_progress = [0] * total_tasks

    def update_progress():
        total = sum(task_progress)
        percent = total / total_tasks
        progress_bar['value'] = percent * 100

    for index, ip in enumerate(all_hosts):
        def make_callback(i):
            return lambda progress: task_progress.__setitem__(i, progress) or update_progress()
        threading.Thread(target=scan_ip, args=(ip, start_port, end_port, make_callback(index)), daemon=True).start()

def save_results(data):
    file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
    if file_path:
        with open(file_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["IP", "Hostname", "Port", "Service", "Protocol", "Status", "Banner", "Description", "Latency (ms)"])
            writer.writerows(data)
        messagebox.showinfo("Saved", f"Results saved to {file_path}")

def run_nmap_scan(ip):
    if not shutil.which("nmap"):
        messagebox.showerror("Nmap Missing", "Nmap is not installed or not in PATH.")
        return

    try:
        output = subprocess.check_output(["nmap", "-sV", "-O", str(ip)], text=True)
        result_window = tk.Toplevel()
        result_window.title(f"Nmap Scan Results - {ip}")
        text = tk.Text(result_window, wrap="word")
        text.insert("1.0", output)
        text.pack(expand=True, fill="both")
    except Exception as e:
        messagebox.showerror("Nmap Error", str(e))

def show_network_graph(results):
    if not results:
        messagebox.showinfo("No Data", "Scan first to show network map.")
        return

    G = nx.Graph()
    ips = set()
    for ip, hostname, port, service, proto, status, banner, desc, latency in results:
        if ip not in ips:
            G.add_node(ip, label=hostname)
            ips.add(ip)
        G.add_edge(ip, f"{service.upper()}:{port}")

    pos = nx.spring_layout(G, seed=42)
    plt.figure(figsize=(10, 6))
    nx.draw(G, pos, with_labels=True, node_color='skyblue', edge_color='gray', font_size=8, node_size=1500)
    labels = nx.get_node_attributes(G, 'label')
    nx.draw_networkx_labels(G, pos, labels=labels, font_color='black')
    plt.title("Network Service Map")
    plt.show()

def create_gui():
    root = tk.Tk()
    root.title("Advanced Network Scanner")
    root.geometry("1000x650")

    frame_top = tk.Frame(root)
    frame_top.pack(pady=5)

    tk.Label(frame_top, text="Network (CIDR):").grid(row=0, column=0, padx=5)
    cidr_entry = tk.Entry(frame_top, width=20)
    cidr_entry.insert(0, "192.168.1.0/24")
    cidr_entry.grid(row=0, column=1, padx=5)

    tk.Label(frame_top, text="Start Port:").grid(row=0, column=2)
    start_port_entry = tk.Entry(frame_top, width=6)
    start_port_entry.insert(0, "1")
    start_port_entry.grid(row=0, column=3)

    tk.Label(frame_top, text="End Port:").grid(row=0, column=4)
    end_port_entry = tk.Entry(frame_top, width=6)
    end_port_entry.insert(0, "1024")
    end_port_entry.grid(row=0, column=5)

    columns = ("IP", "Hostname", "Port", "Service", "Protocol", "Status", "Banner", "Description", "Latency (ms)")
    tree = ttk.Treeview(root, columns=columns, show='headings')
    for col in columns:
        tree.heading(col, text=col)
        tree.column(col, anchor="w", width=110)
    tree.pack(expand=True, fill="both", pady=10)

    progress_bar = ttk.Progressbar(root, orient="horizontal", length=400, mode="determinate")
    progress_bar.pack(pady=5)

    filter_var = tk.StringVar()
    tk.Label(root, text="\U0001F50D Filter:").pack()
    filter_entry = tk.Entry(root, textvariable=filter_var, width=40)
    filter_entry.pack(pady=2)

    def apply_filter():
        query = filter_var.get().lower()
        for row in tree.get_children():
            values = [str(v).lower() for v in tree.item(row)["values"]]
            tree.item(row, tags=())
            if not any(query in v for v in values):
                tree.item(row, tags=("hidden",))
        tree.tag_configure("hidden", foreground="gray75")

    filter_var.trace("w", lambda *args: apply_filter())

    results = []

    def on_scan():
        try:
            start_port = int(start_port_entry.get())
            end_port = int(end_port_entry.get())
            if not (0 < start_port <= end_port <= 65535):
                raise ValueError
        except ValueError:
            messagebox.showerror("Invalid Ports", "Enter valid port numbers (1-65535).")
            return
        start_scan(cidr_entry.get(), start_port, end_port, tree, results, progress_bar)

    def on_save():
        if results:
            save_results(results)
        else:
            messagebox.showinfo("No Data", "No results to save.")

    def on_nmap():
        selected = tree.selection()
        if not selected:
            messagebox.showinfo("Select IP", "Select a row to run nmap.")
            return
        ip = tree.item(selected[0])["values"][0]
        run_nmap_scan(ip)

    button_frame = tk.Frame(root)
    button_frame.pack(pady=10)

    tk.Button(button_frame, text="Start Scan", command=on_scan).grid(row=0, column=0, padx=10)
    tk.Button(button_frame, text="Save to CSV", command=on_save).grid(row=0, column=1, padx=10)
    tk.Button(button_frame, text="Run Nmap on Selected", command=on_nmap).grid(row=0, column=2, padx=10)
    tk.Button(button_frame, text="Show Network Map", command=lambda: show_network_graph(results)).grid(row=0, column=3, padx=10)

    root.after(100, update_tree, tree, results)
    root.mainloop()

if __name__ == "__main__":
    create_gui()
