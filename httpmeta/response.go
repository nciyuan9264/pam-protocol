package httpmeta

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/bytedance/gopkg/cloud/metainfo"
)

const (
	MetadataKey         = "x-pam-http-response"
	CurrentVersion      = 1
	MaxEncodedBytes     = 16 << 10
	MaxHeaders          = 32
	MaxHeaderValues     = 64
	MaxHeaderNameBytes  = 64
	MaxHeaderValueBytes = 4 << 10
	MaxCookies          = 8
	MaxCookieNameBytes  = 256
	MaxCookieValueBytes = 4 << 10
	MaxCookiePathBytes  = 1 << 10
	MaxBodyOmitPaths    = 16
)

type CookieAction string

const (
	CookieSet    CookieAction = "set"
	CookieDelete CookieAction = "delete"
)

type ResponseMeta struct {
	Version       int                 `json:"version"`
	StatusCode    int                 `json:"statusCode,omitempty"`
	Headers       map[string][]string `json:"headers,omitempty"`
	Cookies       []CookieMutation    `json:"cookies,omitempty"`
	BodyOmitPaths []string            `json:"bodyOmitPaths,omitempty"`
}

type CookieMutation struct {
	Action        CookieAction `json:"action"`
	Name          string       `json:"name"`
	Value         string       `json:"value,omitempty"`
	Path          string       `json:"path,omitempty"`
	ExpiresAtUnix int64        `json:"expiresAtUnix,omitempty"`
	MaxAge        int          `json:"maxAge,omitempty"`
	HTTPOnly      bool         `json:"httpOnly"`
	SameSite      string       `json:"sameSite,omitempty"`
}

var allowedResponseHeaders = map[string]struct{}{
	"cache-control":       {},
	"content-disposition": {},
	"etag":                {},
	"last-modified":       {},
	"location":            {},
	"retry-after":         {},
	"www-authenticate":    {},
}

func Encode(meta ResponseMeta) (string, error) {
	if err := Validate(meta); err != nil {
		return "", err
	}
	payload, err := json.Marshal(meta)
	if err != nil {
		return "", fmt.Errorf("encode HTTP response metadata: %w", err)
	}
	if len(payload) > MaxEncodedBytes {
		return "", fmt.Errorf("HTTP response metadata exceeds %d bytes", MaxEncodedBytes)
	}
	return string(payload), nil
}

func Decode(payload string) (ResponseMeta, error) {
	if len(payload) > MaxEncodedBytes {
		return ResponseMeta{}, fmt.Errorf("HTTP response metadata exceeds %d bytes", MaxEncodedBytes)
	}
	if err := rejectDuplicateJSONKeys(payload); err != nil {
		return ResponseMeta{}, err
	}
	decoder := json.NewDecoder(bytes.NewBufferString(payload))
	decoder.DisallowUnknownFields()
	var meta ResponseMeta
	if err := decoder.Decode(&meta); err != nil {
		return ResponseMeta{}, fmt.Errorf("decode HTTP response metadata: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return ResponseMeta{}, err
	}
	if err := Validate(meta); err != nil {
		return ResponseMeta{}, err
	}
	return meta, nil
}

func Send(ctx context.Context, meta ResponseMeta) error {
	payload, err := Encode(meta)
	if err != nil {
		return err
	}
	if !metainfo.SendBackwardValue(ctx, MetadataKey, payload) {
		return fmt.Errorf("backward metadata is unavailable")
	}
	return nil
}

func Receive(ctx context.Context) (ResponseMeta, bool, error) {
	payload, ok := metainfo.RecvBackwardValue(ctx, MetadataKey)
	if !ok || strings.TrimSpace(payload) == "" {
		return ResponseMeta{}, false, nil
	}
	meta, err := Decode(payload)
	return meta, true, err
}

func Validate(meta ResponseMeta) error {
	if meta.Version != CurrentVersion {
		return fmt.Errorf("unsupported HTTP response metadata version %d", meta.Version)
	}
	if meta.StatusCode != 0 && (meta.StatusCode < http.StatusOK || meta.StatusCode > 599) {
		return fmt.Errorf("invalid HTTP status code %d", meta.StatusCode)
	}
	if len(meta.Headers) > MaxHeaders {
		return fmt.Errorf("HTTP response metadata has too many headers")
	}
	canonicalNames := make(map[string]struct{}, len(meta.Headers))
	headerValueCount := 0
	for name, values := range meta.Headers {
		canonical := http.CanonicalHeaderKey(strings.TrimSpace(name))
		if canonical == "" || len(canonical) > MaxHeaderNameBytes || !validToken(canonical) {
			return fmt.Errorf("invalid HTTP response header name %q", name)
		}
		lowerName := strings.ToLower(canonical)
		if _, exists := canonicalNames[lowerName]; exists {
			return fmt.Errorf("duplicate HTTP response header %q", canonical)
		}
		canonicalNames[lowerName] = struct{}{}
		if _, ok := allowedResponseHeaders[strings.ToLower(canonical)]; !ok {
			return fmt.Errorf("HTTP response header %q is not allowed", canonical)
		}
		if len(values) == 0 {
			return fmt.Errorf("HTTP response header %q has no values", canonical)
		}
		headerValueCount += len(values)
		if headerValueCount > MaxHeaderValues {
			return fmt.Errorf("HTTP response metadata has too many header values")
		}
		for _, value := range values {
			if len(value) > MaxHeaderValueBytes || containsControl(value) {
				return fmt.Errorf("invalid value for HTTP response header %q", canonical)
			}
		}
	}
	if len(meta.Cookies) > MaxCookies {
		return fmt.Errorf("HTTP response metadata has too many cookies")
	}
	cookieKeys := make(map[string]struct{}, len(meta.Cookies))
	for _, mutation := range meta.Cookies {
		if err := validateCookie(mutation); err != nil {
			return err
		}
		path := mutation.Path
		if path == "" {
			path = "/"
		}
		key := mutation.Name + "\x00" + path
		if _, exists := cookieKeys[key]; exists {
			return fmt.Errorf("duplicate mutation for cookie %q and path %q", mutation.Name, path)
		}
		cookieKeys[key] = struct{}{}
	}
	if len(meta.BodyOmitPaths) > MaxBodyOmitPaths {
		return fmt.Errorf("HTTP response metadata has too many body omit paths")
	}
	bodyPaths := make(map[string]struct{}, len(meta.BodyOmitPaths))
	for _, pointer := range meta.BodyOmitPaths {
		if !validJSONPointer(pointer) {
			return fmt.Errorf("invalid body omit JSON pointer %q", pointer)
		}
		if _, exists := bodyPaths[pointer]; exists {
			return fmt.Errorf("duplicate body omit JSON pointer %q", pointer)
		}
		bodyPaths[pointer] = struct{}{}
	}
	return nil
}

func IsAllowedResponseHeader(name string) bool {
	_, ok := allowedResponseHeaders[strings.ToLower(http.CanonicalHeaderKey(strings.TrimSpace(name)))]
	return ok
}

func rejectDuplicateJSONKeys(payload string) error {
	decoder := json.NewDecoder(strings.NewReader(payload))
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("decode HTTP response metadata: %w", err)
	}
	if err := consumeJSONValue(decoder, token); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return fmt.Errorf("decode trailing HTTP response metadata: %w", err)
		}
		return fmt.Errorf("HTTP response metadata contains multiple JSON values")
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder, token json.Token) error {
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("decode HTTP response metadata key: %w", err)
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("HTTP response metadata object key is not a string")
			}
			if _, exists := keys[key]; exists {
				return fmt.Errorf("HTTP response metadata contains duplicate JSON key %q", key)
			}
			keys[key] = struct{}{}
			valueToken, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("decode HTTP response metadata value for %q: %w", key, err)
			}
			if err := consumeJSONValue(decoder, valueToken); err != nil {
				return err
			}
		}
		if _, err := decoder.Token(); err != nil {
			return fmt.Errorf("decode HTTP response metadata object: %w", err)
		}
	case '[':
		for decoder.More() {
			itemToken, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("decode HTTP response metadata array: %w", err)
			}
			if err := consumeJSONValue(decoder, itemToken); err != nil {
				return err
			}
		}
		if _, err := decoder.Token(); err != nil {
			return fmt.Errorf("decode HTTP response metadata array: %w", err)
		}
	default:
		return fmt.Errorf("invalid HTTP response metadata delimiter %q", delimiter)
	}
	return nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err == io.EOF {
		return nil
	} else if err != nil {
		return fmt.Errorf("decode trailing HTTP response metadata: %w", err)
	}
	return fmt.Errorf("HTTP response metadata contains multiple JSON values")
}

func validateCookie(mutation CookieMutation) error {
	if mutation.Action != CookieSet && mutation.Action != CookieDelete {
		return fmt.Errorf("invalid cookie action %q", mutation.Action)
	}
	if strings.TrimSpace(mutation.Name) != mutation.Name || mutation.Name == "" ||
		len(mutation.Name) > MaxCookieNameBytes {
		return fmt.Errorf("invalid cookie name %q", mutation.Name)
	}
	if len(mutation.Value) > MaxCookieValueBytes {
		return fmt.Errorf("cookie %q value exceeds %d bytes", mutation.Name, MaxCookieValueBytes)
	}
	path := mutation.Path
	if path == "" {
		path = "/"
	}
	if len(path) > MaxCookiePathBytes || !strings.HasPrefix(path, "/") ||
		containsControl(path) || strings.Contains(path, ";") {
		return fmt.Errorf("invalid path for cookie %q", mutation.Name)
	}
	if containsControl(mutation.Value) {
		return fmt.Errorf("invalid value for cookie %q", mutation.Name)
	}
	if mutation.SameSite != strings.TrimSpace(mutation.SameSite) {
		return fmt.Errorf("invalid SameSite for cookie %q", mutation.Name)
	}
	switch strings.ToLower(mutation.SameSite) {
	case "", "lax", "strict", "none":
	default:
		return fmt.Errorf("invalid SameSite for cookie %q", mutation.Name)
	}
	switch mutation.Action {
	case CookieSet:
		if mutation.ExpiresAtUnix < 0 || mutation.MaxAge < 0 {
			return fmt.Errorf("invalid lifetime for cookie %q", mutation.Name)
		}
		if mutation.ExpiresAtUnix != 0 && mutation.MaxAge != 0 {
			return fmt.Errorf("cookie %q cannot set both expiresAtUnix and maxAge", mutation.Name)
		}
	case CookieDelete:
		if mutation.Value != "" || mutation.ExpiresAtUnix != 0 || mutation.MaxAge != 0 {
			return fmt.Errorf("delete mutation for cookie %q cannot set value or lifetime", mutation.Name)
		}
	}
	cookie := &http.Cookie{Name: mutation.Name, Value: mutation.Value, Path: path}
	if err := cookie.Valid(); err != nil {
		return fmt.Errorf("invalid cookie %q: %w", mutation.Name, err)
	}
	return nil
}

func validJSONPointer(value string) bool {
	if value == "" || !strings.HasPrefix(value, "/") {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] != '~' {
			continue
		}
		if index+1 >= len(value) || (value[index+1] != '0' && value[index+1] != '1') {
			return false
		}
		index++
	}
	return !containsControl(value)
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
