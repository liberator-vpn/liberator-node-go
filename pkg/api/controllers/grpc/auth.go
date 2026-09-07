package grpc

import (
	"context"
	"crypto/subtle"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// UnaryAuthInterceptor требует заголовок "authorization: Bearer <secret>",
// где secret совпадает с общим ключом ноды.
func UnaryAuthInterceptor(secret string) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "metadata is not provided")
		}

		values := md.Get("authorization")
		if len(values) == 0 {
			return nil, status.Error(codes.Unauthenticated, "authorization token is missing")
		}

		authHeader := values[0]
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			return nil, status.Error(codes.Unauthenticated, "authorization header format must be 'Bearer <secret>'")
		}

		if !secureEqual(parts[1], secret) {
			return nil, status.Error(codes.Unauthenticated, "invalid secret")
		}

		return handler(ctx, req)
	}
}

// secureEqual сравнивает строки без раннего выхода (constant-time).
func secureEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
