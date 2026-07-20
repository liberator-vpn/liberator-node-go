sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv4.tcp_congestion_control=bbr
sudo sysctl -w net.ipv4.conf.liberator.rp_filter=0

protoc \
  --proto_path=pkg/api/proto \
  --go_out=pkg/api/grpc --go_opt=paths=source_relative \
  --go-grpc_out=pkg/api/grpc --go-grpc_opt=paths=source_relative \
  pkg/api/proto/firewall.proto pkg/api/proto/peers.proto


  host-route:
    image: alpine:3.22
    container_name: vpn-host-route
    restart: unless-stopped

    network_mode: host

    cap_add:
      - NET_ADMIN

    depends_on:
      - vpn

    environment:
      VPN_SUBNET: 10.8.1.0/24
      VPN_CONTAINER_IP: 172.29.172.3
      DOCKER_BRIDGE: amn0
      EXTERNAL_INTERFACE: eth0

    command:
      - /bin/sh
      - -ec
      - |
        apk add --no-cache iptables

        sysctl -w net.ipv4.ip_forward=1

        ip route replace "$VPN_SUBNET" \
          via "$VPN_CONTAINER_IP" \
          dev "$DOCKER_BRIDGE"

        iptables -C FORWARD \
          -i "$DOCKER_BRIDGE" \
          -o "$EXTERNAL_INTERFACE" \
          -s "$VPN_SUBNET" \
          -j ACCEPT 2>/dev/null ||
        iptables -A FORWARD \
          -i "$DOCKER_BRIDGE" \
          -o "$EXTERNAL_INTERFACE" \
          -s "$VPN_SUBNET" \
          -j ACCEPT

        iptables -C FORWARD \
          -i "$EXTERNAL_INTERFACE" \
          -o "$DOCKER_BRIDGE" \
          -d "$VPN_SUBNET" \
          -m conntrack \
          --ctstate ESTABLISHED,RELATED \
          -j ACCEPT 2>/dev/null ||
        iptables -A FORWARD \
          -i "$EXTERNAL_INTERFACE" \
          -o "$DOCKER_BRIDGE" \
          -d "$VPN_SUBNET" \
          -m conntrack \
          --ctstate ESTABLISHED,RELATED \
          -j ACCEPT

        iptables -t nat -C POSTROUTING \
          -s "$VPN_SUBNET" \
          -o "$EXTERNAL_INTERFACE" \
          -j MASQUERADE 2>/dev/null ||
        iptables -t nat -A POSTROUTING \
          -s "$VPN_SUBNET" \
          -o "$EXTERNAL_INTERFACE" \
          -j MASQUERADE

        sleep infinity