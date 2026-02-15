package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		wantKey     string
		wantErrMsg  string
	}{
		{
			name:       "no authorization header",
			headers:    http.Header{},
			wantKey:    "",
			wantErrMsg: "no authorization header included",
		},
		{
			name:       "malformed header missing scheme",
			headers:    http.Header{"Authorization": []string{"Bearer token123"}},
			wantKey:    "",
			wantErrMsg: "malformed authorization header",
		},
		{
			name:       "malformed header no space",
			headers:    http.Header{"Authorization": []string{"ApiKey"}},
			wantKey:    "",
			wantErrMsg: "malformed authorization header",
		},
		{
			name:    "valid api key",
			headers: http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			wantKey: "my-secret-key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tt.headers)
			if tt.wantErrMsg != "" {
				if err == nil {
					t.Fatalf("expected error %q, got nil", tt.wantErrMsg)
				}
				if err.Error() != tt.wantErrMsg {
					t.Fatalf("expected error %q, got %q", tt.wantErrMsg, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotKey != tt.wantKey {
				t.Fatalf("expected key %q, got %q", tt.wantKey, gotKey)
			}
		})
	}
}
