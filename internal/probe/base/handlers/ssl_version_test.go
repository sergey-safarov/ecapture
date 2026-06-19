// Copyright 2022 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package handlers

import "testing"

func TestIsValidSSLVersion(t *testing.T) {
	tests := []struct {
		version int32
		valid   bool
	}{
		{Tls12Version, true},
		{Tls13Version, true},
		{Dtls12Version, true},
		{Dtls10Version, true},
		{Dtls13Version, true},
		{0x9999, false},
	}

	for _, tt := range tests {
		if got := IsValidSSLVersion(tt.version); got != tt.valid {
			t.Errorf("IsValidSSLVersion(0x%04x) = %v, want %v", tt.version, got, tt.valid)
		}
	}
}

func TestUsesMasterSecretKeylog(t *testing.T) {
	tests := []struct {
		version int32
		want    bool
	}{
		{Tls12Version, true},
		{Dtls12Version, true},
		{Dtls10Version, true},
		{Tls13Version, false},
		{Dtls13Version, false},
	}

	for _, tt := range tests {
		if got := UsesMasterSecretKeylog(tt.version); got != tt.want {
			t.Errorf("UsesMasterSecretKeylog(0x%04x) = %v, want %v", tt.version, got, tt.want)
		}
	}
}

func TestUsesTLS13Keylog(t *testing.T) {
	tests := []struct {
		version int32
		want    bool
	}{
		{Tls13Version, true},
		{Dtls13Version, true},
		{Dtls12Version, false},
		{Tls12Version, false},
	}

	for _, tt := range tests {
		if got := UsesTLS13Keylog(tt.version); got != tt.want {
			t.Errorf("UsesTLS13Keylog(0x%04x) = %v, want %v", tt.version, got, tt.want)
		}
	}
}

func TestKeylogHandler_Handle_DTLS12(t *testing.T) {
	writer := newMockKeylogWriter()
	handler := NewKeylogHandler(writer)

	clientRandom := make([]byte, Ssl3RandomSize)
	masterKey := make([]byte, MasterSecretMaxLen)
	for i := range clientRandom {
		clientRandom[i] = byte(i + 1)
	}
	for i := range masterKey {
		masterKey[i] = byte(i + 50)
	}

	event := &mockMasterSecretEvent{
		version:      Dtls12Version,
		clientRandom: clientRandom,
		masterKey:    masterKey,
	}

	err := handler.Handle(event)
	if err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}

	output := writer.String()
	if output == "" {
		t.Fatal("expected keylog output for DTLS 1.2")
	}
	if output[:len("CLIENT_RANDOM ")] != "CLIENT_RANDOM " {
		t.Errorf("DTLS 1.2 should use CLIENT_RANDOM format, got: %s", output)
	}
}
