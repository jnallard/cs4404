sudo iptables --flush
sudo iptables -A FORWARD -p udp -j NFQUEUE --queue-num 0
sudo iptables -A INPUT -p udp -j NFQUEUE --queue-num 0
sudo iptables -A OUTPUT -p udp -j NFQUEUE --queue-num 0
sudo iptables -A FORWARD -p 200 -j NFQUEUE --queue-num 0
sudo iptables -A INPUT -p 200 -j NFQUEUE --queue-num 0
sudo iptables -A OUTPUT -p 200 -j NFQUEUE --queue-num 0
sudo ./routeRecord
