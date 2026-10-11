package metadata

import (
	"context"
	"strings"
	"testing"

	"github.com/bytedance/gopkg/cloud/metainfo"
)

func TestClientMiddlewarePropagatesRequestAndIdentity(t *testing.T) {
	ctx, err := WithRequestInfo(context.Background(), RequestInfo{
		RequestID:  "req-1",
		ClientIP:   "203.0.113.4",
		UserAgent:  "test",
		HTTPMethod: "patch",
		HTTPPath:   "/platform/users/7",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err = WithIdentity(ctx, "7", []string{"admin"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err = WithUserToken(ctx, "access")
	if err != nil {
		t.Fatal(err)
	}
	ctx, err = WithRefreshToken(ctx, "refresh")
	if err != nil {
		t.Fatal(err)
	}
	ctx, err = WithMachineToken(ctx, "machine")
	if err != nil {
		t.Fatal(err)
	}

	next := func(ctx context.Context, _, _ any) error {
		for key, want := range map[string]string{
			RequestIDKey: "req-1", ClientIPKey: "203.0.113.4", UserAgentKey: "test",
			HTTPMethodKey: "PATCH", HTTPPathKey: "/platform/users/7",
			UserIDKey: "7", UserRolesKey: `["admin"]`, UserTokenKey: "access",
			RefreshTokenKey: "refresh", MachineTokenKey: "machine",
		} {
			if got, ok := metainfo.GetValue(ctx, key); !ok || got != want {
				t.Fatalf("metadata %s = %q, %v; want %q", key, got, ok, want)
			}
		}
		return nil
	}
	if err := ClientMiddleware(next)(ctx, nil, nil); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityFromMetadataDefensivelyCopiesRoles(t *testing.T) {
	ctx := metainfo.WithValue(context.Background(), UserIDKey, "7")
	ctx = metainfo.WithValue(ctx, UserRolesKey, `["admin","operator"]`)
	identity, ok, err := IdentityFromContext(ctx)
	if err != nil || !ok || identity.UserID != "7" || len(identity.Roles) != 2 {
		t.Fatalf("identity = %+v, %v, %v", identity, ok, err)
	}
	identity.Roles[0] = "changed"
	again, _, err := IdentityFromContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if again.Roles[0] != "admin" {
		t.Fatalf("metadata roles were mutated: %v", again.Roles)
	}
}

func TestMetadataReadersRejectMalformedValues(t *testing.T) {
	tests := []struct {
		name string
		ctx  context.Context
		read func(context.Context) error
	}{
		{
			name: "invalid client IP",
			ctx:  metainfo.WithValue(context.Background(), ClientIPKey, "not-an-ip"),
			read: func(ctx context.Context) error {
				_, err := RequestInfoFromContext(ctx)
				return err
			},
		},
		{
			name: "roles without identity",
			ctx:  metainfo.WithValue(context.Background(), UserRolesKey, `["admin"]`),
			read: func(ctx context.Context) error {
				_, _, err := IdentityFromContext(ctx)
				return err
			},
		},
		{
			name: "malformed roles",
			ctx: func() context.Context {
				ctx := metainfo.WithValue(context.Background(), UserIDKey, "7")
				return metainfo.WithValue(ctx, UserRolesKey, `["admin"`)
			}(),
			read: func(ctx context.Context) error {
				_, _, err := IdentityFromContext(ctx)
				return err
			},
		},
		{
			name: "duplicate roles",
			ctx: func() context.Context {
				ctx := metainfo.WithValue(context.Background(), UserIDKey, "7")
				return metainfo.WithValue(ctx, UserRolesKey, `["admin","ADMIN"]`)
			}(),
			read: func(ctx context.Context) error {
				_, _, err := IdentityFromContext(ctx)
				return err
			},
		},
		{
			name: "credential control character",
			ctx:  metainfo.WithValue(context.Background(), UserTokenKey, "token\nvalue"),
			read: func(ctx context.Context) error {
				_, _, err := UserTokenFromContext(ctx)
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.read(test.ctx); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestMetadataWritersRejectInvalidValues(t *testing.T) {
	if _, err := WithRequestInfo(context.Background(), RequestInfo{HTTPMethod: "BAD METHOD"}); err == nil {
		t.Fatal("expected invalid HTTP method error")
	}
	if _, err := WithIdentity(context.Background(), "", nil); err == nil {
		t.Fatal("expected missing user ID error")
	}
	if _, err := WithMachineToken(context.Background(), strings.Repeat("x", MaxCredentialBytes+1)); err == nil {
		t.Fatal("expected oversized credential error")
	}
}
