# Advanced-Network-Utility-with-a-Graphical-User-Interface-GUI / Port Scanner

This project is an Advanced Network Utility built using Python, primarily leveraging the Scapy library and a Tkinter graphical user interface (GUI). Its main purpose is to act as a packet sniffer and dissector, allowing you to:

Monitor Network Traffic: Capture live network packets flowing through a specific network interface on your Mac (like your Wi-Fi or Ethernet adapter).

Dissect and Analyze Packets: Break down captured packets to reveal details about various network layers and protocols, such as:

Link Layer: Source and Destination MAC addresses.

Network Layer: Source and Destination IP addresses (IPv4 and IPv6), ARP requests/replies, ICMP (ping) messages.

Transport Layer: Source and Destination Ports for TCP and UDP, TCP flags.

Application Layer (Advanced): Enhancing the information displayed for common protocols like HTTP and DNS

Filter Traffic: Apply filters based on IP address or port number to focus only on specific traffic of interest, reducing clutter.

Large Packet Detection: Flagging packets that exceed a certain size, which can sometimes indicate unusual data transfers.

Common Malicious Ports: Alerting if traffic is observed on ports often associated with malware

Track Basic Flow Statistics: Keep a count of packets belonging to the same "conversation" or flow.

![IMG_1897](https://github.com/user-attachments/assets/e5a4ecd9-e388-4c50-b6d7-80d423ca578c)

[advanced_network_utility.zip](https://github.com/user-attachments/files/21208883/advanced_network_utility.zip)


Essentially, it gives you a window into the otherwise invisible world of data flowing on your network.

Components and How They Interact
The utility integrates several key technologies:

Python: The core programming language.

Scapy: A powerful Python library for packet manipulation. It's the engine that handles:

Sniffing: Capturing raw packets from the network interface.

![IMG_1856 (1)](https://github.com/user-attachments/assets/44ab58a5-9b27-4e46-92f5-3cb43d418c1e)

Before I started the GUI and sniffer, I put VVV
conf.verb = 10
# Set verbosity to a high level
>> sniff (iface="en®", count=5, prn=lambda x: x.summary(), timeout=10) # Add a timeout
Ether / IPv6 / ICMPv6ND_NS / ICMPv6 Neighbor Discovery Option - Source
Link-Layer Address 16:73:8e:db:05:2a
Ether / IPv6 / ICMPv6ND_NS / ICMPv6 Neighbor Discovery Option - Source Link-Layer Address 16:73:8e:db:05:2a
Ether / IPv6 / ICMP6 Neighbor Discovery - Neighbor Advertisement (tgt: fe80::1872:18df: f91e:7742)
Ether IPv6 / ICMPv6 Neighbor Discovery - Neighbor Advertisement (tgt: 2600:4040:79c7:2300:7dc7:2a2e:d519:7ef3)
Ether / ARP who has 192.168.1.243 says 192.168.1.1
< Sniffed: TCP:0 UDP:0 ICMP:0 Other:5>


Dissection: Parsing the raw packet data into its various layers (Ethernet, IP, TCP, UDP, DNS, HTTP, etc.) and extracting meaningful information.

Tkinter: Python's standard GUI toolkit. It's used to create the visual elements of the application, including:

Input fields for the network interface, IP filter, and port filter.

Buttons to start, stop, and clear the sniffing process.

A large scrolled text area to display the dissected packet information.

A status bar provides feedback to the user.

Threading: The application uses Python's threading module to run the packet sniffing process in a separate thread from the main GUI thread. This is crucial because:

Packet sniffing is a continuous, blocking operation. If it ran on the main GUI thread, the GUI would freeze and become unresponsive.


The GUI remains responsive by putting it in a separate thread, allowing you to click buttons and interact while packets are being captured in the background.
queue Module: A queue. The object queue is used as a thread-safe communication channel. Packets captured by the sniffing thread are placed into this queue. The main GUI thread then periodically checks this queue, pulls out packets, and updates the display. This prevents potential data corruption that could occur if multiple threads tried to access the same GUI elements directly.



The Journey: How It Was Made
Creating this utility involved several steps and troubleshooting processes:

Code Provision: The initial Python script containing the core logic for sniffing, GUI creation, and inter-thread communication.

Saving the Script: I saved the Python code to a file on my Mac, specifically advanced_network_utility.py.

Dependency Installation: I installed the scapy library using pip install scapy in your Terminal, which is essential for the script's core functionality.

Running from Terminal: The script is executed from the macOS Terminal. Due to the low-level network access required for sniffing, it had to be run with administrator (root) privileges using sudo python3.

sudo python3 /Users/divine/Desktop/advanced_network_utility.py -i en0 (This pulls up the sniffer and gives me the options to Start, Stop ,and put IP and Port filters)

Interface Identification: I learned to use the ifconfig (and netstat -rn | grep default) command in Terminal to identify your active network interface (which turned out to be en0 on your Mac). This interface name was then passed to the script using the -i argument.



Challenges Encountered and How They Were Solved
My journey wasn't entirely smooth, and I tackled several common challenges:

Problem: File Saving with Incorrect Extension (.py.txt)

Issue: TextEdit, macOS's default text editor, often tries to be "helpful" by automatically appending .txt or .rtf extensions to your .py file, leading to names like advanced_network_utility.py.txt. This made the Python interpreter unable to find the correct file.



Solution:

Initial Advice: I first tried to guide you to uncheck the "Hide Extension" option in TextEdit's save dialog and Finder preferences.

Definitive Fix: When those proved stubborn, the most reliable solution was to use the Terminal's mv (move/rename) command, providing the exact old filename (e.g., advanced_network_utility.py.txt) and the exact desired new filename (advanced_network_utility.py). This command bypasses graphical editor quirks and forces the correct naming.

Problem: "No such file or directory" when running from Terminal (cd issues)

Issue: When trying to run the script, Terminal reported that it couldn't find the file, even after saving. This happened because the Terminal's "current directory" was not the folder where the script was saved.

Solution:

Navigation: I clarified the use of the cd command (e.g., cd Desktop or cd Documents) to change the Terminal's current directory to where the script was located.

Foolproof Method: The most robust solution was to use drag-and-drop. By typing sudo python3  (with a space) and then dragging the script file directly from Finder into the Terminal window, the full, correct path to the script was automatically inserted, eliminating any directory navigation errors.

Problem: Scapy Permissions (Silent Failure)

Issue: When first trying to run the script, it wouldn't start sniffing or throw an obvious error. This was due to the requirement for Scapy to have root (administrator) privileges to access raw network packets.

Solution: I correctly instructed you to prefix the Python command with sudo (e.g., sudo python3 ...). This elevates the script's permissions, allowing it to perform low-level network operations. You would then be prompted for your Mac's password.

Problem: Identifying the Correct Network Interface

Issue: The ifconfig command can output many network interfaces (lo0, en0, en1, utun0, awdl0, etc.), and it's not immediately obvious which one is connected to the internet.

Solution: I guided you to look for key indicators in the ifconfig output:

status: active

UP and RUNNING flags.

An inet IPv4 address that looks like a typical local network IP (e.g., 192.168.1.X).

I also used netstat -rn | grep default to definitively identify the interface handling your internet traffic's "default route," which confirmed en0 as the correct choice.

Problem: Packets Captured but Not Displayed in GUI (The "Blank GUI" Issue)

Issue: This was the most challenging and subtle problem. Even though debug messages in the Terminal showed that Scapy was successfully capturing packets and putting them into the internal packet_queue, the GUI's text area remained blank.

Root Cause: The process_packet_queue function, which runs on the main GUI thread to display packets, was inadvertently stopping its periodic rescheduling. This happened because it performed an initial check when the GUI application first launched (__init__), and at that time, the self.is_sniffing flag was False (since you hadn't clicked "Start Sniffing" yet). Based on this False state, it decided there was nothing to do, and critically, it stopped rescheduling itself via self.master.after().

Solution: The core fix involved restructuring the process_packet_queue scheduling:

I removed the initial scheduling of process_packet_queue from the __init__ method.

I ensured that process_packet_queue is explicitly scheduled only when you click "Start Sniffing". At that point, self.is_sniffing is set to True, so the process_packet_queue will correctly enter its loop and continuously reschedule itself, pulling packets from the queue and updating the display.

Additional try-except blocks and debug prints were added to process_packet_queue and _dissect_and_display_packet to confirm that packets were being pulled from the queue and that the GUI insertion step was succeeding, helping to track this subtle bug down.

Problem: Small Text in GUI

Issue: The default font size for the output text in the ScrolledText widget was too small for comfortable reading.

![IMG_1868](https://github.com/user-attachments/assets/e87a9418-92e9-48ae-aa28-3497d4f5008e)

Solution: We adjusted the font_output variable in the SnifferApp class to a larger size (e.g., ("Consolas", 11)), which directly controls the text size in the main display area. We also made minor adjustments to other font sizes (font_large, font_medium maintain a balanced and readable aesthetic throughout the GUI.

Through these iterative steps of coding, debugging, and targeted problem-solving, I successfully got my Advanced Network Utility up and running, providing a powerful tool for network analysis!

![IMG_1895 (1)](https://github.com/user-attachments/assets/758c73d3-b467-4d19-a064-2a2898234e4d)

PORT SCANNER

A tool often used by malicious actors or penetration testers. However, in our context, it became a controlled, test instrument to ensure my defensive (detection) mechanism was correctly calibrated and implemented. I made a script to ensure that it would pick up any unusual traffic from the ports.

import socket
import sys

# Define the base IP address (first three octets)
# This should be the network segment you want to scan.
# For example, if your network is 192.168.1.x, set it to "192.168.1."
ip_base = "192.168.1." # Notice the dot at the end

# Define the range for the LAST octet of the IP address
start_ip_suffix = 160  # Starting last octet (e.g., 192.168.1.160)
end_ip_suffix = 165    # Ending last octet (e.g., 192.168.1.165)

ports_to_scan = range(1, 21) # Ports 1-20

print(f"Attempting to scan IP addresses from {ip_base}{start_ip_suffix} to {ip_base}{end_ip_suffix} on ports {min(ports_to_scan)}-{max(ports_to_scan)}...")

for i in range(start_ip_suffix, end_ip_suffix + 1):
    target_ip = f"{ip_base}{i}" # This will now correctly form IPs like 192.168.1.160, 192.168.1.161, etc.
    print(f"\n--- Scanning IP: {target_ip} ---")
    for port in ports_to_scan:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1) # Short timeout
        try:
            sock.connect((target_ip, port))
            print(f"  Port {port} OPEN on {target_ip}")
        except (socket.timeout, ConnectionRefusedError):
            # print(f"  Port {port} closed/filtered on {target_ip}") # Uncomment if you want to see closed ports
            pass # Suppress output for closed/filtered ports for cleaner output
        except Exception as e:
            print(f"  Error checking port {port} on {target_ip}: {e}")
        finally:
            sock.close()
print("\nPort scan simulation complete for all target IPs.")

![IMG_1900](https://github.com/user-attachments/assets/7552fac1-0046-4168-a0ad-99f40b4bdccb)




























































































































































