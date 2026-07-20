protoc \
  --proto_path=pkg/api/proto \
  --go_out=pkg/api/grpc --go_opt=paths=source_relative \
  --go-grpc_out=pkg/api/grpc --go-grpc_opt=paths=source_relative \
  pkg/api/proto/firewall.proto pkg/api/proto/peers.proto