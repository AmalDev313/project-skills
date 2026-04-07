
"""
# Example usage:
# scan_port("127.0.01", 135") # Scans port 135 on localhost windows RPC
#TIME_WAIT exists because the connection was fully established and the OS must safely close it.
#socket.connect() will complete the TCP three-way handshake.
#syn-syn/ack-ack is performed and the connection is established. and clsed with FIN-FIN/ACK-ACK.
#After the connection is closed, the socket goes into TIME_WAIT state to ensure all packets have been properly handled.
#If you try to reconnect to the same port during this TIME_WAIT period, you may encounter issues.  
#To avoid this, you can either wait for the TIME_WAIT period to expire or use a different port for subsequent connections. 
# #This is a standard behavior in TCP/IP networking to ensure reliable communication.
 
#issues with a full tcp scan is that it can be time-consuming, especially when scanning a large range of ports or multiple IP addresses.
#Each port scan involves establishing a TCP connection, which can take time, particularly if many ports are closed or filtered.

#1. Network Congestion: Scanning multiple ports can generate significant network traffic, potentially leading to congestion and affecting the performance of other network services.
#2. Firewall and IDS Detection: Many networks have firewalls and Intrusion Detection Systems (IDS) that can detect and block port scanning activities, leading to incomplete or inaccurate results.
#3. False Positives/Negatives: Some ports may appear open or closed due to network configurations, firewalls, or other factors, leading to false positives or negatives in the scan results.   
#4. Legal and Ethical Considerations: Port scanning can be considered intrusive or malicious activity in some contexts, so it's important to ensure you have permission to scan the target network or system.
#5. Resource Intensive: Scanning a large number of ports can consume significant system resources, potentially impacting the performance of the scanning machine.
#6. Timeouts and Delays: Some ports may respond slowly or not at all, leading to timeouts that can prolong the scanning process.
#7. Limited by Network Policies: Some networks may have policies in place that restrict or limit port scanning activities, which can affect the ability to perform a comprehensive scan.
#8. Privilege Requirements: On some operating systems, scanning certain ports (especially those below 1024) may require elevated privileges, which can limit the ability to perform scans without proper permissions.
#9. Dynamic Port Assignments: Some services use dynamic or ephemeral ports, which can change frequently, making it challenging to identify open ports accurately.
#10. Incomplete Coverage: A TCP scan may not cover all possible ports or protocols, potentially missing open ports that use different protocols (e.g., UDP).
#11. Impact on Target Systems: Aggressive port scanning can potentially disrupt services on the target system, leading to unintended consequences.
#12. Detection by Security Systems: Many security systems are designed to detect and respond to port scanning activities, which can lead to alerts or blocks against the scanning IP address.
#13. Limited by Network Topology: The presence of NAT (Network Address Translation) or other network configurations can affect the visibility of certain ports, leading to incomplete scan results.
#14. Time Consumption: Scanning a large range of ports can be time-consuming, especially if many ports are closed or filtered, leading to longer scan times.
#15. Inconsistent Results: Network conditions can change over time, leading to inconsistent scan results if the same scan is performed multiple times.
#16. Privilege Escalation Risks: In some cases, attempting to scan ports without proper permissions can lead to security risks or vulnerabilities, especially if the scanning tool is exploited by malicious actors.
#17. Limited by Tool Capabilities: The effectiveness of a TCP scan can be limited by the capabilities of the scanning tool being used, which may not support all features or protocols.


#issues with scanning ports below 1024 may require elevated privileges (e.g., running as administrator or root) on some operating systems.
#Ports below 1024 are known as "well-known ports" and are typically reserved for system or privileged services.
#Scanning these ports without proper permissions may result in inaccurate results or permission denied errors.

#A syn scan (also known as half-open scan) is a type of port scan that sends SYN packets to a target port and analyzes the response to determine if the port is open, closed, or filtered.from socket import socket, AF_INET, SOCK_STREAM, timeout
#there is no fully established connection in a syn scan, making it stealthier and less likely to be detected by intrusion detection systems (IDS) or firewalls.
#no time_wait state is created because the TCP three-way handshake is not completed.


#TCP connect scans cause TIME_WAIT because the OS tracks fully established connections until they are safely closed, while SYN scans avoid it by never completing the handshake, leaving no persistent kernel state.


=============================================================
  INTERMEDIATE TCP PORT SCANNER
  A step up from single-threaded scanning — uses a thread
  pool so many ports are checked simultaneously instead of
  one at a time.
=============================================================

KEY CONCEPTS TO UNDERSTAND BEFORE CODING

  TCP (Transmission Control Protocol)
  ─────────────────────────────────────
  TCP is a *connection-oriented* protocol. Before any data
  is sent, both ends must complete a "three-way handshake":
    1. Client → SYN       (I want to connect)
    2. Server → SYN-ACK   (OK, I'm ready)
    3. Client → ACK       (Great, connection open)

  This is called a FULL CONNECT scan (what we do here).
  The OS kernel completes the entire handshake.

  Why use a full connect vs a SYN (half-open) scan?
  ─────────────────────────────────────────────────
    • Full connect: easier, no root/admin needed, but
      leaves TIME_WAIT entries in the OS socket table
      and is more easily detected by IDS/firewalls.
    • SYN scan: sends SYN, reads the SYN-ACK response,
      then drops the connection before ACK — stealth,
      but requires raw socket privileges (root/admin).
      This is what Nmap uses by default.

  TIME_WAIT
  ─────────
  After a full TCP connection closes, the OS keeps the
  socket in TIME_WAIT for ~60–120 s to ensure any stray
  packets for that session are safely discarded.
  Scanning thousands of ports rapidly can fill this table.

  Threading vs async vs single-threaded
  ──────────────────────────────────────
    • Single-threaded (your original): scans one port,
      waits up to 1 s for a timeout, then moves on. With
      65 535 ports that's potentially 18+ hours.
    • ThreadPoolExecutor (this script): spawns N worker
      threads. Each thread handles one port at a time.
      With 100 threads and 1 s timeout → ~655 s max for
      full range. Practical for smaller port ranges.
    • Async I/O (asyncio): even faster; no OS thread
      overhead. Used by professional tools.
    • Raw socket / SYN scan: fastest + stealthiest, but
      requires elevated privileges.

  Port categories
  ───────────────
    0–1023   : Well-known (HTTP=80, HTTPS=443, SSH=22 …)
    1024–49151: Registered (common apps, databases …)
    49152–65535: Dynamic / ephemeral (OS assigns these
                  for outbound connections)

  Common well-known ports (you should memorise these)
  ────────────────────────────────────────────────────
    21  FTP       22  SSH       23  Telnet
    25  SMTP      53  DNS       80  HTTP
    110 POP3      143 IMAP      443 HTTPS
    445 SMB       3306 MySQL   3389 RDP
    5432 PostgreSQL  6379 Redis  8080 HTTP alt
"""

import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ─────────────────────────────────────────────────────────────────────────────
# WELL-KNOWN PORT NAMES
# ─────────────────────────────────────────────────────────────────────────────
# A dictionary mapping common port numbers to their service names.
# socket.getservbyport() can do this too, but it varies by OS, so we keep
# our own small lookup table for reliability.
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 135: "MS-RPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt",
    27017: "MongoDB",
}


# ─────────────────────────────────────────────────────────────────────────────
# BANNER GRABBING
# ─────────────────────────────────────────────────────────────────────────────
# Banner grabbing: after a TCP connection is established, some services
# immediately send a welcome message (their "banner") before you say anything.
# e.g., SSH sends "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
#       FTP sends  "220 FTP Server Ready"
# This lets us fingerprint the service version without any extra tools.
def grab_banner(sock: socket.socket) -> str:
    """
    Try to read the first bytes the server sends after connection.
    Returns a decoded string, or empty string if nothing arrives.
    """
    try:
        # settimeout here is shorter — we don't want to wait long
        # just to see if a banner arrives.
        sock.settimeout(0.5)
        # recv(1024): read up to 1024 bytes from the socket buffer.
        # The OS kernel has already placed incoming data there.
        banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
        return banner[:80]  # truncate very long banners
    except Exception:
        return ""


# ─────────────────────────────────────────────────────────────────────────────
# CORE SCAN FUNCTION (runs in each worker thread)
# ─────────────────────────────────────────────────────────────────────────────
def scan_port(ip: str, port: int, timeout: float, grab: bool) -> dict:
    """
    Attempt a full TCP connect to (ip, port).

    Returns a dict so all data travels together through the thread pool.
    This is better than global lists, which need locks to be thread-safe.

    Parameters
    ──────────
    ip      : target IPv4 address
    port    : TCP port number (1–65535)
    timeout : seconds to wait for a response before giving up
    grab    : whether to attempt banner grabbing

    Return value keys
    ──────────────────
    port    : int   — the port number
    open    : bool  — True if connection succeeded
    service : str   — name from our lookup table (may be empty)
    banner  : str   — banner text (may be empty)
    error   : str   — error description if not open
    """
    result = {
        "port": port,
        "open": False,
        "service": COMMON_PORTS.get(port, ""),
        "banner": "",
        "error": "",
    }

    # AF_INET   = address family IPv4  (use AF_INET6 for IPv6)
    # SOCK_STREAM = TCP stream socket  (SOCK_DGRAM would be UDP)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        # connect_ex returns an error code (0 = success) instead of raising.
        # This is preferred in threaded code — exceptions are slower to handle
        # at scale, and we expect most ports to be closed.
        err_code = sock.connect_ex((ip, port))

        if err_code == 0:
            # Error code 0 means the TCP handshake completed successfully.
            # The port is OPEN — a service is listening.
            result["open"] = True
            if grab:
                result["banner"] = grab_banner(sock)

        else:
            # Non-zero = OS-level error.
            # 111 (ECONNREFUSED) → port is CLOSED (firewall sent RST or ICMP)
            # 110 (ETIMEDOUT)    → port is FILTERED (firewall silently drops)
            # We treat both as "not open" for simplicity.
            result["error"] = f"errno {err_code}"

    except socket.timeout:
        # settimeout() expired — likely a filtered port (no response at all).
        result["error"] = "timeout (filtered?)"

    except OSError as exc:
        # Catch-all for unexpected OS-level socket errors.
        result["error"] = str(exc)

    finally:
        # ALWAYS close the socket, even if an exception occurred.
        # The 'finally' block runs regardless of success or failure.
        # Not closing sockets leaks file descriptors — the OS has a hard limit.
        sock.close()

    return result


# ─────────────────────────────────────────────────────────────────────────────
# THREADED SCANNER
# ─────────────────────────────────────────────────────────────────────────────
def run_scan(ip: str, start: int, end: int, threads: int,
             timeout: float, grab: bool, verbose: bool) -> list:
    """
    Dispatch scan_port() across a thread pool and collect results.

    ThreadPoolExecutor
    ──────────────────
    Python's Global Interpreter Lock (GIL) limits true parallel CPU work,
    but I/O-bound tasks (like waiting for network packets) release the GIL,
    so threads genuinely run in parallel here.
    With 100 threads and 1-second timeout, we check ~100 ports per second
    instead of 1 per second in single-threaded mode — 100× speedup.

    as_completed()
    ──────────────
    Returns futures in the order they *finish*, not the order they were
    submitted. This lets us print results in real-time as ports respond,
    rather than waiting for all threads to finish first.
    """
    ports = range(start, end + 1)
    total = len(ports)
    open_ports = []

    print(f"\n  Scanning {ip}  ports {start}–{end}  ({total} ports)")
    print(f"  Threads: {threads}   Timeout: {timeout}s   "
          f"Banner grab: {'yes' if grab else 'no'}")
    print(f"  Started: {datetime.now().strftime('%H:%M:%S')}\n")

    # The 'with' statement is a context manager.
    # When the block exits (normally or via exception), the executor
    # automatically calls shutdown(wait=True), draining all threads cleanly.
    with ThreadPoolExecutor(max_workers=threads) as executor:

        # submit() sends a function call to the thread pool and returns a
        # Future — a placeholder for a result that isn't ready yet.
        # We build a dict {future: port_number} so we can look up which
        # port a future belongs to when it completes.
        futures = {
            executor.submit(scan_port, ip, port, timeout, grab): port
            for port in ports
        }

        completed = 0
        for future in as_completed(futures):
            completed += 1

            # future.result() blocks until this specific future is done,
            # then returns the dict returned by scan_port().
            result = future.result()

            # Progress indicator — \r overwrites the current terminal line
            # so we get a live counter without flooding the screen.
            print(f"\r  Progress: {completed}/{total}", end="", flush=True)

            if result["open"]:
                open_ports.append(result)
                service_tag = f"  [{result['service']}]" if result["service"] else ""
                banner_tag = f"  »  {result['banner']}" if result["banner"] else ""
                print(f"\r  ✓  Port {result['port']:>5}{service_tag}{banner_tag}")

            elif verbose and result["error"]:
                # verbose mode shows closed/filtered ports too —
                # useful for learning; turn off for production scans.
                print(f"\r  ✗  Port {result['port']:>5}  {result['error']}")

    print(f"\n\n  Finished: {datetime.now().strftime('%H:%M:%S')}")
    return open_ports


# ─────────────────────────────────────────────────────────────────────────────
# INPUT VALIDATION HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def validate_ip(ip: str) -> bool:
    """
    Validate an IPv4 address by asking the OS to parse it.
    socket.inet_aton() raises OSError for malformed addresses.
    """
    try:
        socket.inet_aton(ip)
        return True
    except OSError:
        return False


def resolve_host(host: str) -> str:
    """
    Resolve a hostname (e.g. 'scanme.nmap.org') to an IP address.
    socket.gethostbyname() queries DNS. Returns None on failure.

    DNS resolution itself can fail for many reasons:
      • No internet connection
      • The hostname doesn't exist
      • The DNS server is unreachable
    """
    try:
        return socket.gethostbyname(host)
    except socket.gaierror as exc:
        print(f"  [!] DNS resolution failed: {exc}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# MAIN — USER INPUT & ORCHESTRATION
# ─────────────────────────────────────────────────────────────────────────────
def main():
    print("=" * 62)
    print("  INTERMEDIATE PORT SCANNER")
    print("  Educational use only. Only scan systems you own or have")
    print("  written permission to test.")
    print("=" * 62)

    # ── Target ──────────────────────────────────────────────────────────────
    raw_target = input("\n  Target IP or hostname: ").strip()

    # Accept hostnames as well as bare IPs
    if validate_ip(raw_target):
        ip = raw_target
    else:
        print(f"  Resolving '{raw_target}' via DNS …")
        ip = resolve_host(raw_target)
        if not ip:
            sys.exit(1)
        print(f"  Resolved → {ip}")

    # ── Port range ───────────────────────────────────────────────────────────
    try:
        start = int(input("  Start port [1]:     ").strip() or 1)
        end   = int(input("  End port   [1024]:  ").strip() or 1024)
    except ValueError:
        print("  [!] Ports must be integers.")
        sys.exit(1)

    if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
        print("  [!] Ports must be 1–65535 and start ≤ end.")
        sys.exit(1)

    # ── Advanced options ─────────────────────────────────────────────────────
    threads = int(input("  Threads   [100]:    ").strip() or 100)
    timeout = float(input("  Timeout s [1.0]:    ").strip() or 1.0)

    # y/n prompts with safe defaults
    grab    = input("  Banner grab?  [y/N]: ").strip().lower() == "y"
    verbose = input("  Verbose mode? [y/N]: ").strip().lower() == "y"

    # ── Run ──────────────────────────────────────────────────────────────────
    open_ports = run_scan(ip, start, end, threads, timeout, grab, verbose)

    # ── Summary ──────────────────────────────────────────────────────────────
    print("\n" + "=" * 62)
    if open_ports:
        print(f"  {len(open_ports)} open port(s) found on {ip}:\n")
        print(f"  {'PORT':<8}{'SERVICE':<16}BANNER")
        print("  " + "-" * 56)
        for r in sorted(open_ports, key=lambda x: x["port"]):
            print(f"  {r['port']:<8}{r['service']:<16}{r['banner']}")
    else:
        print("  No open ports found in the specified range.")
    print("=" * 62 + "\n")


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT GUARD
# ─────────────────────────────────────────────────────────────────────────────
# if __name__ == "__main__" ensures main() only runs when you execute this
# file directly (python networkscanner.py), NOT when another script imports it.
# Without this guard, importing the module would immediately launch a scan.
if __name__ == "__main__":
    main()


#Professional scanners avoid 1-thread-per-port designs because (1) they exhaust kernel socket/file-descriptor limits, (2) they flood the TCP TIME_WAIT table and cripple the host, and (3) they cause massive context-switch overhead, overwhelming the scheduler and destroying performance.
#Instead, they use asynchronous I/O, multiplexing, or thread pools to efficiently manage many simultaneous connections without overwhelming system resources.
