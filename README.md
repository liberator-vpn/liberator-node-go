sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv4.tcp_congestion_control=bbr
sudo sysctl -w net.ipv4.conf.liberator.rp_filter=0

protoc \
  --proto_path=pkg/api/proto \
  --go_out=pkg/api/grpc --go_opt=paths=source_relative \
  --go-grpc_out=pkg/api/grpc --go-grpc_opt=paths=source_relative \
  pkg/api/proto/firewall.proto pkg/api/proto/peers.proto pkg/api/proto/mesh.proto pkg/api/proto/router.proto \
  pkg/api/proto/node.proto