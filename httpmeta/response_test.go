package httpmeta

import (
	"context"
	"strings"
	"testing"

	"github.com/bytedance/gopkg/cloud/metainfo"
)

func TestResponseMetaRoundTrip(t *testing.T) {
	want := ResponseMeta{
		Version:    CurrentVersion,
		StatusCode: 201,
		Headers:    map[string][]string{"Location": {"/items/1"}},
		Cookies: []CookieMutation{
			{Action: CookieSet, Name: "access_token", Value: "secret", Path: "/", HTTPOnly: true, SameSite: "lax"},
			{Action: CookieDelete, Name: "refresh_token", Path: "/", HTTPOnly: true, SameSite: "lax"},
		},
		BodyOmitPaths: []string{"/data/internal_note"},
	}
	encoded, err := Encode(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if got.StatusCode != want.StatusCode || len(got.Cookies) != 2 || got.BodyOmitPaths[0] != "/data/internal_note" {
		t.Fatalf("decoded metadata = %+v", got)
	}
}

func TestSendAndReceive(t *testing.T) {
	serverCtx := metainfo.WithBackwardValuesToSend(context.Background())
	meta := ResponseMeta{Version: CurrentVersion, StatusCode: 204}
	if err := Send(serverCtx, meta); err != nil {
		t.Fatal(err)
	}
	payload, ok := metainfo.GetBackwardValueToSend(serverCtx, MetadataKey)
	if !ok {
		t.Fatal("backward metadata was not sent")
	}
	clientCtx := metainfo.WithBackwardValues(context.Background())
	if !metainfo.SetBackwardValue(clientCtx, MetadataKey, payload) {
		t.Fatal("backward metadata receiver is unavailable")
	}
	got, exists, err := Receive(clientCtx)
	if err != nil || !exists || got.StatusCode != 204 {
		t.Fatalf("Receive() = %+v, %v, %v", got, exists, err)
	}
}

func TestResponseMetaRejectsUnsafeValues(t *testing.T) {
	tests := []ResponseMeta{
		{Version: CurrentVersion, StatusCode: 199},
		{Version: CurrentVersion, Headers: map[string][]string{"Set-Cookie": {"a=b"}}},
		{Version: CurrentVersion, Headers: map[string][]string{"Location": {"/ok\r\nX-Bad: 1"}}},
		{Version: CurrentVersion, Headers: map[string][]string{"Location": {"/a"}, "location": {"/b"}}},
		{Version: CurrentVersion, Headers: map[string][]string{"Location": {}}},
		{Version: CurrentVersion, Cookies: []CookieMutation{{Action: CookieSet, Name: "bad name", Value: "x"}}},
		{Version: CurrentVersion, Cookies: []CookieMutation{
			{Action: CookieSet, Name: "session", Value: "a", Path: "/"},
			{Action: CookieDelete, Name: "session", Path: "/"},
		}},
		{Version: CurrentVersion, Cookies: []CookieMutation{{
			Action: CookieSet, Name: "session", Value: "a", ExpiresAtUnix: 1, MaxAge: 1,
		}}},
		{Version: CurrentVersion, Cookies: []CookieMutation{{
			Action: CookieDelete, Name: "session", Value: "must-be-empty",
		}}},
		{Version: CurrentVersion, Cookies: []CookieMutation{{
			Action: CookieSet, Name: "session", Value: "a", Path: "/bad;path",
		}}},
		{Version: CurrentVersion, BodyOmitPaths: []string{"data/internal_note"}},
		{Version: CurrentVersion, BodyOmitPaths: []string{"/data/internal_note", "/data/internal_note"}},
	}
	for _, meta := range tests {
		if _, err := Encode(meta); err == nil {
			t.Fatalf("Encode(%+v) succeeded", meta)
		}
	}
}

func TestDecodeRejectsOversizedMetadata(t *testing.T) {
	_, err := Decode(strings.Repeat("x", MaxEncodedBytes+1))
	if err == nil {
		t.Fatal("expected size validation error")
	}
}

func TestDecodeRejectsDuplicateJSONKeys(t *testing.T) {
	payloads := []string{
		`{"version":1,"version":1}`,
		`{"version":1,"headers":{"Location":["/a"],"Location":["/b"]}}`,
		`{"version":1,"cookies":[{"action":"set","name":"session","name":"other"}]}`,
	}
	for _, payload := range payloads {
		if _, err := Decode(payload); err == nil {
			t.Fatalf("Decode(%s) succeeded", payload)
		}
	}
}
