package metadata

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/bytedance/gopkg/cloud/metainfo"
	"github.com/cloudwego/kitex/pkg/endpoint"
)

const (
	RequestIDKey    = "x-pam-request-id"
	ClientIPKey     = "x-pam-client-ip"
	UserAgentKey    = "x-pam-user-agent"
	HTTPMethodKey   = "x-pam-http-method"
	HTTPPathKey     = "x-pam-http-path"
	UserIDKey       = "x-pam-user-id"
	UserRolesKey    = "x-pam-user-roles"
	UserTokenKey    = "x-pam-user-token"
	RefreshTokenKey = "x-pam-refresh-token"
	MachineTokenKey = "x-pam-machine-token"

	MaxRequestIDBytes  = 128
	MaxUserAgentBytes  = 512
	MaxHTTPMethodBytes = 32
	MaxHTTPPathBytes   = 4 << 10
	MaxUserIDBytes     = 128
	MaxRoles           = 32
	MaxRoleBytes       = 128
	MaxCredentialBytes = 16 << 10
)

type Identity struct {
	UserID string
	Roles  []string
}

type RequestInfo struct {
	RequestID  string
	ClientIP   string
	UserAgent  string
	HTTPMethod string
	HTTPPath   string
}

type contextKey uint8

const (
	requestInfoContextKey contextKey = iota
	identityContextKey
	userTokenContextKey
	refreshTokenContextKey
	machineTokenContextKey
)

func WithRequestInfo(ctx context.Context, value RequestInfo) (context.Context, error) {
	value = normalizeRequestInfo(value)
	if err := validateRequestInfo(value); err != nil {
		return ctx, err
	}
	return context.WithValue(ctx, requestInfoContextKey, value), nil
}

func RequestInfoFromContext(ctx context.Context) (RequestInfo, error) {
	if value, ok := ctx.Value(requestInfoContextKey).(RequestInfo); ok {
		value = normalizeRequestInfo(value)
		return value, validateRequestInfo(value)
	}
	value := normalizeRequestInfo(RequestInfo{
		RequestID:  valueFromMetadata(ctx, RequestIDKey),
		ClientIP:   valueFromMetadata(ctx, ClientIPKey),
		UserAgent:  valueFromMetadata(ctx, UserAgentKey),
		HTTPMethod: valueFromMetadata(ctx, HTTPMethodKey),
		HTTPPath:   valueFromMetadata(ctx, HTTPPathKey),
	})
	return value, validateRequestInfo(value)
}

func WithIdentity(ctx context.Context, userID string, roles []string) (context.Context, error) {
	identity := normalizeIdentity(Identity{UserID: userID, Roles: roles})
	if err := validateIdentity(identity); err != nil {
		return ctx, err
	}
	return context.WithValue(ctx, identityContextKey, identity), nil
}

func IdentityFromContext(ctx context.Context) (Identity, bool, error) {
	if identity, ok := ctx.Value(identityContextKey).(Identity); ok {
		identity = normalizeIdentity(identity)
		if err := validateIdentity(identity); err != nil {
			return Identity{}, false, err
		}
		return identity, true, nil
	}
	userID := valueFromMetadata(ctx, UserIDKey)
	encodedRoles := valueFromMetadata(ctx, UserRolesKey)
	if userID == "" {
		if encodedRoles != "" {
			return Identity{}, false, fmt.Errorf("%s is present without %s", UserRolesKey, UserIDKey)
		}
		return Identity{}, false, nil
	}
	var roles []string
	if encodedRoles != "" {
		if err := json.Unmarshal([]byte(encodedRoles), &roles); err != nil {
			return Identity{}, false, fmt.Errorf("decode %s: %w", UserRolesKey, err)
		}
	}
	identity := normalizeIdentity(Identity{UserID: userID, Roles: roles})
	if err := validateIdentity(identity); err != nil {
		return Identity{}, false, err
	}
	return identity, true, nil
}

func WithUserToken(ctx context.Context, token string) (context.Context, error) {
	return withCredential(ctx, userTokenContextKey, token)
}

func UserTokenFromContext(ctx context.Context) (string, bool, error) {
	return credentialFromContext(ctx, userTokenContextKey, UserTokenKey)
}

func WithRefreshToken(ctx context.Context, token string) (context.Context, error) {
	return withCredential(ctx, refreshTokenContextKey, token)
}

func RefreshTokenFromContext(ctx context.Context) (string, bool, error) {
	return credentialFromContext(ctx, refreshTokenContextKey, RefreshTokenKey)
}

func WithMachineToken(ctx context.Context, token string) (context.Context, error) {
	return withCredential(ctx, machineTokenContextKey, token)
}

func MachineTokenFromContext(ctx context.Context) (string, bool, error) {
	return credentialFromContext(ctx, machineTokenContextKey, MachineTokenKey)
}

func ClientMiddleware(next endpoint.Endpoint) endpoint.Endpoint {
	return func(ctx context.Context, req, resp any) error {
		info, err := RequestInfoFromContext(ctx)
		if err != nil {
			return err
		}
		ctx = withMetadataValue(ctx, RequestIDKey, info.RequestID)
		ctx = withMetadataValue(ctx, ClientIPKey, info.ClientIP)
		ctx = withMetadataValue(ctx, UserAgentKey, info.UserAgent)
		ctx = withMetadataValue(ctx, HTTPMethodKey, info.HTTPMethod)
		ctx = withMetadataValue(ctx, HTTPPathKey, info.HTTPPath)
		if identity, ok, err := IdentityFromContext(ctx); err != nil {
			return err
		} else if ok {
			ctx = withMetadataValue(ctx, UserIDKey, identity.UserID)
			encodedRoles, err := json.Marshal(identity.Roles)
			if err != nil {
				return fmt.Errorf("encode %s: %w", UserRolesKey, err)
			}
			ctx = withMetadataValue(ctx, UserRolesKey, string(encodedRoles))
		}
		if token, ok, err := UserTokenFromContext(ctx); err != nil {
			return err
		} else if ok {
			ctx = metainfo.WithValue(ctx, UserTokenKey, token)
		}
		if token, ok, err := RefreshTokenFromContext(ctx); err != nil {
			return err
		} else if ok {
			ctx = metainfo.WithValue(ctx, RefreshTokenKey, token)
		}
		if token, ok, err := MachineTokenFromContext(ctx); err != nil {
			return err
		} else if ok {
			ctx = metainfo.WithValue(ctx, MachineTokenKey, token)
		}
		return next(ctx, req, resp)
	}
}

func withCredential(ctx context.Context, key contextKey, token string) (context.Context, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return ctx, nil
	}
	if err := validateCredential(token); err != nil {
		return ctx, err
	}
	return context.WithValue(ctx, key, token), nil
}

func credentialFromContext(ctx context.Context, contextKey contextKey, metadataKey string) (string, bool, error) {
	if token, ok := ctx.Value(contextKey).(string); ok && strings.TrimSpace(token) != "" {
		token = strings.TrimSpace(token)
		if err := validateCredential(token); err != nil {
			return "", false, fmt.Errorf("invalid %s: %w", metadataKey, err)
		}
		return token, true, nil
	}
	token, ok := metainfo.GetValue(ctx, metadataKey)
	token = strings.TrimSpace(token)
	if !ok || token == "" {
		return "", false, nil
	}
	if err := validateCredential(token); err != nil {
		return "", false, fmt.Errorf("invalid %s: %w", metadataKey, err)
	}
	return token, true, nil
}

func valueFromMetadata(ctx context.Context, key string) string {
	value, _ := metainfo.GetValue(ctx, key)
	return strings.TrimSpace(value)
}

func withMetadataValue(ctx context.Context, key, value string) context.Context {
	if strings.TrimSpace(value) == "" {
		return ctx
	}
	return metainfo.WithValue(ctx, key, value)
}

func normalizeRequestInfo(value RequestInfo) RequestInfo {
	value.RequestID = strings.TrimSpace(value.RequestID)
	value.ClientIP = strings.TrimSpace(value.ClientIP)
	value.UserAgent = strings.TrimSpace(value.UserAgent)
	value.HTTPMethod = strings.ToUpper(strings.TrimSpace(value.HTTPMethod))
	value.HTTPPath = strings.TrimSpace(value.HTTPPath)
	return value
}

func validateRequestInfo(value RequestInfo) error {
	if err := validateText("request ID", value.RequestID, MaxRequestIDBytes); err != nil {
		return err
	}
	if value.ClientIP != "" && net.ParseIP(value.ClientIP) == nil {
		return fmt.Errorf("invalid client IP %q", value.ClientIP)
	}
	if err := validateText("user agent", value.UserAgent, MaxUserAgentBytes); err != nil {
		return err
	}
	if err := validateText("HTTP method", value.HTTPMethod, MaxHTTPMethodBytes); err != nil {
		return err
	}
	if value.HTTPMethod != "" && !validToken(value.HTTPMethod) {
		return fmt.Errorf("invalid HTTP method %q", value.HTTPMethod)
	}
	if err := validateText("HTTP path", value.HTTPPath, MaxHTTPPathBytes); err != nil {
		return err
	}
	if value.HTTPPath != "" && value.HTTPPath[0] != '/' {
		return fmt.Errorf("invalid HTTP path %q", value.HTTPPath)
	}
	return nil
}

func normalizeIdentity(value Identity) Identity {
	value.UserID = strings.TrimSpace(value.UserID)
	roles := make([]string, 0, len(value.Roles))
	for _, role := range value.Roles {
		roles = append(roles, strings.TrimSpace(role))
	}
	value.Roles = roles
	return value
}

func validateIdentity(value Identity) error {
	if value.UserID == "" {
		return fmt.Errorf("user ID is required")
	}
	if err := validateText("user ID", value.UserID, MaxUserIDBytes); err != nil {
		return err
	}
	if len(value.Roles) > MaxRoles {
		return fmt.Errorf("identity has more than %d roles", MaxRoles)
	}
	seen := make(map[string]struct{}, len(value.Roles))
	for _, role := range value.Roles {
		if role == "" {
			return fmt.Errorf("identity contains an empty role")
		}
		if err := validateText("role", role, MaxRoleBytes); err != nil {
			return err
		}
		key := strings.ToLower(role)
		if _, ok := seen[key]; ok {
			return fmt.Errorf("identity contains duplicate role %q", role)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validateCredential(value string) error {
	if len(value) > MaxCredentialBytes {
		return fmt.Errorf("credential exceeds %d bytes", MaxCredentialBytes)
	}
	if containsControl(value) {
		return fmt.Errorf("credential contains a control character")
	}
	return nil
}

func validateText(name, value string, limit int) error {
	if len(value) > limit {
		return fmt.Errorf("%s exceeds %d bytes", name, limit)
	}
	if containsControl(value) {
		return fmt.Errorf("%s contains a control character", name)
	}
	return nil
}

func validToken(value string) bool {
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character <= 32 || character >= 127 || strings.ContainsRune("()<>@,;:\\\"/[]?={} ", rune(character)) {
			return false
		}
	}
	return value != ""
}

func containsControl(value string) bool {
	for _, character := range value {
		if character < 32 || character == 127 {
			return true
		}
	}
	return false
}
