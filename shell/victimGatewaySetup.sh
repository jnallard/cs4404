sudo ip route add 10.4.12.1 via 10.4.12.4;sudo ip route add 10.4.12.2 via 10.4.12.4;sudo ip route add 10.4.12.3 via 10.4.12.4;sudo ip route add 10.4.12.4 via 10.4.12.4;sudo ip route add 10.4.12.6 via 10.4.12.6;sudo sysctl -w net.ipv4.ip_forward=1