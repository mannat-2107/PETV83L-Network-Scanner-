import socket, ipaddress, threading, time, subprocess, shutil, csv
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import matplotlib.pyplot as plt
import networkx as nx

scan_results = []
stop_flag = threading.Event()
total_ports_to_scan = 0
ports_scanned_so_far = 0

PORT_INFO = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 3306: "MySQL",
    3389: "RDP", 8080: "Alt HTTP"
}

def scan_port(ip, port):
    try:
        s = socket.socket()
        s.settimeout(0.3)
        start = time.time()
        s.connect((ip, port))
        latency = round((time.time() - start) * 1000, 2)
        try:
            banner = s.recv(1024).decode(errors="ignore").strip()
        except:
            banner = "No banner"
        s.close()
        service = socket.getservbyport(port, "tcp") if port <= 49151 else "Unknown"
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            hostname = "N/A"
        description = PORT_INFO.get(port, "General Service")
        return (ip, hostname, port, service, "TCP", "Open", banner, description, latency)
    except:
        return None

def scan_ip(ip, start_port, end_port, progress_func, update_func):
    global ports_scanned_so_far
    for port in range(start_port, end_port + 1):
        if stop_flag.is_set():
            break
        result = scan_port(str(ip), port)
        if result:
            scan_results.append(result)
            update_func(result)
        ports_scanned_so_far += 1
        progress_func(ports_scanned_so_far)

def start_scan(cidr, start_port, end_port, tree, progress, labels, progress_label):
    global total_ports_to_scan, ports_scanned_so_far
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        messagebox.showerror("Invalid CIDR", "Enter CIDR like 192.168.0.0/24")
        return

    tree.delete(*tree.get_children())
    scan_results.clear()
    stop_flag.clear()
    progress["value"] = 0
    ports_scanned_so_far = 0

    ips = list(net.hosts())
    total_ports_to_scan = len(ips) * (end_port - start_port + 1)

    stats = {"hosts": 0, "open_ports": 0, "latencies": []}

    def update_progress(current):
        percent = (current / total_ports_to_scan) * 100
        progress["value"] = percent
        progress_label.config(text=f"{percent:.1f}%")

    def update_result(result):
        tree.insert("", "end", values=result)
        tree.yview_moveto(1.0)
        stats["open_ports"] += 1
        stats["latencies"].append(result[-1])
        labels["ports"].config(text=f"Open Ports: {stats['open_ports']}")
        labels["min_latency"].config(text=f"Min: {min(stats['latencies']):.1f} ms")
        labels["max_latency"].config(text=f"Max: {max(stats['latencies']):.1f} ms")

    for ip in ips:
        threading.Thread(target=scan_ip, args=(ip, start_port, end_port, update_progress, update_result), daemon=True).start()
        stats["hosts"] += 1
        labels["hosts"].config(text=f"Hosts: {stats['hosts']}")

def save_csv(data):
    file = filedialog.asksaveasfilename(defaultextension=".csv")
    if file:
        with open(file, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["IP", "Hostname", "Port", "Service", "Protocol", "Status", "Banner", "Description", "Latency"])
            writer.writerows(data)
        messagebox.showinfo("Saved", "CSV exported!")

def show_graph(data):
    if not data:
        messagebox.showwarning("No Data", "Scan first to visualize network.")
        return
    G = nx.Graph()
    for ip, _, port, service, *_ in data:
        G.add_node(ip)
        G.add_edge(ip, f"{service}:{port}")
    plt.figure(figsize=(10, 6))
    nx.draw_networkx(G, with_labels=True, node_color="skyblue", edge_color="gray")
    plt.title("Network Graph")
    plt.show()

def toggle_theme(root, dark):
    if dark.get():
        root.tk_setPalette(background="#202124", foreground="white", activeBackground="#3c4043", highlightColor="white")
    else:
        root.tk_setPalette(background="SystemButtonFace", foreground="black")

def create_gui():
    root = tk.Tk()
    root.title("Network Scanner by Mannat")
    root.geometry("1080x720")

    dark = tk.BooleanVar()
    tk.Checkbutton(root, text="🌙 Dark Mode", variable=dark, command=lambda: toggle_theme(root, dark)).pack(anchor="ne")

    top = tk.Frame(root)
    top.pack(pady=5)

    tk.Label(top, text="CIDR:").grid(row=0, column=0)
    cidr = tk.Entry(top, width=18)
    cidr.insert(0, "192.168.1.0/24")
    cidr.grid(row=0, column=1)

    tk.Label(top, text="Start Port:").grid(row=0, column=2)
    sp = tk.Entry(top, width=6)
    sp.insert(0, "1")
    sp.grid(row=0, column=3)

    tk.Label(top, text="End Port:").grid(row=0, column=4)
    ep = tk.Entry(top, width=6)
    ep.insert(0, "1024")
    ep.grid(row=0, column=5)

    columns = ["IP", "Hostname", "Port", "Service", "Protocol", "Status", "Banner", "Description", "Latency"]
    tree = ttk.Treeview(root, columns=columns, show="headings")
    for col in columns:
        tree.heading(col, text=col)
        tree.column(col, anchor="w", width=110)
    tree.pack(expand=True, fill="both", pady=10)

    progress = ttk.Progressbar(root, orient="horizontal", length=500, mode="determinate")
    progress.pack()
    progress_label = tk.Label(root, text="0%")
    progress_label.pack()

    summary = tk.Frame(root)
    summary.pack()
    labels = {
        "hosts": tk.Label(summary, text="Hosts: 0"),
        "ports": tk.Label(summary, text="Open Ports: 0"),
        "min_latency": tk.Label(summary, text="Min: 0 ms"),
        "max_latency": tk.Label(summary, text="Max: 0 ms")
    }
    for i, lbl in enumerate(labels.values()):
        lbl.grid(row=0, column=i, padx=10)

    buttons = tk.Frame(root)
    buttons.pack(pady=10)

    def start():
        try:
            s, e = int(sp.get()), int(ep.get())
        except:
            return messagebox.showerror("Invalid", "Ports must be numbers")
        start_scan(cidr.get(), s, e, tree, progress, labels, progress_label)

    def stop():
        stop_flag.set()
        messagebox.showinfo("Stopped", "Scan stopped.")

    tk.Button(buttons, text="▶️ Start Scan", command=start).grid(row=0, column=0, padx=10)
    tk.Button(buttons, text="⏹️ Stop", command=stop).grid(row=0, column=1, padx=10)
    tk.Button(buttons, text="📁 Save CSV", command=lambda: save_csv(scan_results)).grid(row=0, column=2, padx=10)
    tk.Button(buttons, text="📡 Show Graph", command=lambda: show_graph(scan_results)).grid(row=0, column=3, padx=10)

    root.mainloop()

if __name__ == "__main__":
    create_gui()
