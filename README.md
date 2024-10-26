# ARP Spoof Detector

This program is a socket application that captures network packets using the pcap library to detect potential ARP spoofing attacks. It sniffs network packets on a specified network interface, analyzes ARP packets, and logs potential ARP spoofing incidents.

## Features

- Sniffs network packets on the specified network interface.
- Detects potential ARP spoofing attacks by analyzing ARP packets.
- Maintains a list of known IP-MAC address pairs.
- Logs detected ARP spoofing incidents to a file named `arp_spoof.log`.
- Provides a real-time display of captured packets and detected ARP spoofing attempts.

## Prerequisites

Before compiling and running this program, ensure you have the following installed:

- GCC (GNU Compiler Collection)
- libpcap-dev (Packet Capture library development files)

On Ubuntu or Debian-based systems, you can install libpcap-dev using:

```
sudo apt-get update
sudo apt-get install libpcap-dev
```
For other operating systems, please refer to their respective package management systems or the libpcap documentation.

## Compilation

To compile the program, follow these steps:

1. Save the provided C code in a file named `arp_spoof_detector.c`.
2. Open a terminal and navigate to the directory containing the file.
3. Run the following command to compile the program:

```
gcc -o arp_spoof_detector arp_spoof_detector.c -lpcap
```

This will create an executable named `arp_spoof_detector`.

## Usage

To run the program, use the following command:

```
sudo ./arp_spoof_detector <interface>
```

Replace `<interface>` with the name of the network interface you want to monitor (e.g., eth0, wlan0).

Note: The program requires root privileges to capture packets, so it must be run with `sudo`.

## Output

The program will display information about each captured packet, including:

- Timestamp
- Packet length
- ARP packet details (if applicable)
- Potential ARP spoofing detection alerts

The output will be displayed in real-time on the console.

## Log File

Detected ARP spoofing incidents are logged to a file named `arp_spoof.log` in the same directory as the executable. Each log entry includes:

- Timestamp of the detected incident
- Sender's MAC address
- Sender's IP address

## How It Works

1. The program captures network packets on the specified interface using libpcap.
2. It filters for ARP packets and analyzes their contents.
3. For ARP replies, it checks if the sender's IP-MAC pair is already known.
4. If an unknown pair is encountered, it's added to the list of known pairs.
5. If a known IP is seen with a different MAC address, it's flagged as a potential ARP spoofing attempt.
6. Detected incidents are logged and displayed in real-time.

## Limitations

- This is a basic implementation for educational purposes and may generate false positives.
- It doesn't handle network changes or DHCP-assigned IP addresses dynamically.
- The program stores a limited number of IP-MAC pairs (default: 1000).

## Testing

To test the application, you can simulate ARP spoofing attacks on your network and observe the program's output. Make sure to perform tests in a controlled environment and with proper authorization.

## Security Considerations

- This tool should be used responsibly and only on networks you have permission to monitor.
- It's designed for educational purposes and may not be suitable for production environments without further enhancements.
- Always follow ethical guidelines and legal requirements when using network monitoring tools.

## Troubleshooting

If you encounter any issues:

1. Ensure you have the necessary permissions to capture packets on the specified interface.
2. Verify that libpcap is correctly installed on your system.
3. Check that you're using a valid network interface name.

## Contributing

Contributions to improve the program are welcome. Please submit pull requests or open issues on the project's repository.

## License

This program is provided as-is under the MIT License. See the LICENSE file for details.

## Disclaimer

This software is provided for educational purposes only. The authors are not responsible for any misuse or damage caused by this program. Use at your own risk.
