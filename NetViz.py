import csv
import sys
import time
from datetime import datetime
from collections import deque
from queue import Queue, Empty
from threading import Thread

# Third-party libraries
from scapy.all import sniff, IP, TCP, UDP, conf, ifaces # type: ignore
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.layout import Layout
from rich import box

# ---------- Configuration & Globals ----------
LOG_FILE = "audit_log_v2.csv"
WINDOW_SIZE = 50 
packet_queue = Queue()
console = Console()

class Metrics:
    def __init__(self):
        self.total = 0
        self.corrupt = 0
        self.start_time = time.time()
        self.history = deque(maxlen=15)
        self.window = deque(maxlen=WINDOW_SIZE)

    @property
    def pps(self):
        elapsed = time.time() - self.start_time
        return self.total / max(elapsed, 0.1)

    @property
    def health_score(self):
        if not self.window: return 100.0
        corruption_rate = sum(self.window) / len(self.window)
        return (1.0 - corruption_rate) * 100

stats = Metrics()

# ---------- Logic: Packet Validation ----------
def analyze_corruption(pkt):
    """Deep Packet Inspection for Malicious Signatures."""
    if not pkt.haslayer(IP):
        return True, "NON-IP"
    
    ip = pkt[IP]
    # Check 1: Header Length Mismatch (RFC 791 Violation)
    if ip.len < (ip.ihl * 4):
        return True, "LEN_MISMATCH"
    
    # Check 2: Illegal TCP Flag Combinations
    if pkt.haslayer(TCP):
        flags = pkt[TCP].flags
        # Attack 1: SYN + FIN (Illegal state: Open and Close simultaneously)
        if 'S' in flags and 'F' in flags: 
            return True, "SYN_FIN_ATTACK"
        # Attack 2: SYN + RST (Stealth Scan signature)
        if 'S' in flags and 'R' in flags: 
            return True, "SYN_RST_SCAN"
        # Check 3: Data Offset (Header too small)
        if pkt[TCP].dataofs < 5: 
            return True, "TCP_HDR_SHORT"
        
    return False, "HEALTHY"

# ---------- UI: Dashboard Components ----------
def make_header() -> Panel:
    return Panel(
        f"[bold cyan]INDUSTRIAL NETWORK AUDIT TOOL[/bold cyan] | [white]Log: {LOG_FILE}[/white]",
        style="bold white on blue", box=box.SQUARE
    )

def make_summary_panel() -> Panel:
    health = stats.health_score
    pps = stats.pps
    
    if health > 98:
        status_msg, color = "OPTIMAL", "green"
    elif health > 90:
        status_msg, color = "WARNING", "yellow"
    else:
        status_msg, color = "CRITICAL", "red"
    
    grid = Table.grid(expand=True)
    grid.add_column(justify="left", ratio=1)
    grid.add_column(justify="right", ratio=1)
    
    grid.add_row("Network Throughput:", f"[bold cyan]{pps:.1f} pkts/s[/bold cyan]")
    grid.add_row("Total Traffic:", f"{stats.total} packets")
    grid.add_row("Integrity Failures:", f"[bold red]{stats.corrupt}[/bold red]")
    grid.add_row("Current System Health:", f"[bold {color}]{status_msg} ({health:.1f}%)[/bold {color}]")
    
    return Panel(grid, title="[bold]Real-Time System Health[/bold]", border_style=color, padding=(1, 2))

def make_packet_table() -> Table:
    table = Table(expand=True, box=box.SIMPLE_HEAD)
    table.add_column("Time", style="dim", width=12)
    table.add_column("Source", style="cyan")
    table.add_column("Destination", style="magenta")
    table.add_column("Proto", justify="center", width=8)
    table.add_column("Status", justify="right")

    for p in reversed(stats.history):
        color = "red" if p['bad'] else "green"
        table.add_row(p['ts'], p['src'], p['dst'], p['proto'], f"[{color}]{p['msg']}[/{color}]")
    return table

# ---------- Workers ----------
def logger_worker():
    with open(LOG_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        while True:
            try:
                item = packet_queue.get(timeout=1)
                if item == "STOP": break
                writer.writerow(item)
                packet_queue.task_done()
            except Empty: continue

def sniff_handler(pkt):
    if not pkt.haslayer(IP): return
    
    is_bad, reason = analyze_corruption(pkt)
    stats.total += 1
    if is_bad: stats.corrupt += 1
    stats.window.append(1 if is_bad else 0)
    
    entry = {
        "ts": datetime.now().strftime("%H:%M:%S"),
        "src": pkt[IP].src,
        "dst": pkt[IP].dst,
        "proto": "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "OTHER",
        "bad": is_bad,
        "msg": reason
    }
    stats.history.append(entry)
    packet_queue.put([entry['ts'], entry['src'], entry['dst'], entry['proto'], reason])

# ---------- Main Loop ----------
def run_monitor():
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body", ratio=1),
        Layout(name="footer", size=8)
    )

    log_thread = Thread(target=logger_worker, daemon=True)
    log_thread.start()

    # MENTOR TIP: Show which interface we are using
    # If using localhost test, ensure this says "Loopback"
    console.print(f"[bold yellow]Sniffing on:[/bold yellow] {conf.iface}")

    try:
        with Live(layout, refresh_per_second=4, screen=True):
            layout["header"].update(make_header())
            
            def callback(pkt):
                sniff_handler(pkt)
                layout["body"].update(make_packet_table())
                layout["footer"].update(make_summary_panel())

            # Promiscuous mode allows seeing all traffic on the wire
            sniff(prn=callback, store=False, promisc=True)
            
    except KeyboardInterrupt:
        packet_queue.put("STOP")
        log_thread.join()
        sys.exit(0)

if __name__ == "__main__":
    run_monitor()