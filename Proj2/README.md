# IPK - Computer communications and networks
## 2 project
### Author: Alina Vinogradova, 2BIT
### [xvinog00@stud.fit.vutbr.cz](mailto:xvinog00@stud.fit.vutbr.cz)

Evaluation: 16/20

### Application: packet sniffer in C
Design and implement a network analyzer in C/C++/C# that will be able to
a specific network interface to capture and filter packets.

## File compilation
`make` in the root directory of the project.
```
    $ ls
    
    ipk-sniffer.c Makefile README.md manual.pdf
    
    $ make
    
    gcc ipk-sniffer.c -lpcap -Wall -Werror -o ipk-sniffer
    
    $ ls
     
    ipk-sniffer.c Makefile README.md manual.pdf ipk-sniffer
```

## Execution syntax
`sudo ./ipk-sniffer [-i interface | --interface interface] {-p port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}`

| Command                                         | Description                                                                                                                                                                                      |
|-------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `-i [interface]` nebo `--interface [interface]` | `-i eth0` Just one interface on which to listen. If this parameter is not specified, or if only -i is specified without a value, a list of active interfaces will be printed.                    |
| `-p [port]`                                     | `-p 23`Filters packets on a given interface by port; if this parameter is not specified, all ports are considered; if specified, the port can occur in both the source and destination sections. |
| `-t` nebo `--tcp`                               | Will display only TCP packets.                                                                                                                                                                   |
| `-u` nebo `--udp`                               | Will display only UDP packets.                                                                                                                                                                   |
| `--icmp`                                        | Will display only ICMPv4 and ICMPv6 packets.                                                                                                                                                     |
| `--arp`                                         | Will only display ARP frames.                                                                                                                                                                    |
| `-n num`                                        | `-n 10` Specifies the number of packets to display; if not specified, consider displaying only one packet, i.e. `-n 1`. |

- Unless specific protocols are specified (or if all of them are listed at once), all protocols (i.e. all content, regardless of the protocol) are considered for printing.
- The program can be correctly terminated at any time using Ctrl+C.

## Output format:
| Command | Description                                              |
| --- |----------------------------------------------------------|
| `timestamp` | Time (in RFC3339 format)                                 |
| `src MAC` a `dst MAC` | MAC address with : as separator                          |
| `frame length` | Length (in bytes)                                        |
| `src IP` a `dst IP`| IP address (support v4 but also v6 according to RFC5952) |
| `src port` a `dst port` | Port number                                              |
| `offset_vypsaných_bajtů` | Byte_dump_hexa Byte_dump_ASCII                     |

## For more information check manual.pdf
