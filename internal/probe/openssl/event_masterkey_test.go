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

package openssl

import (
	"testing"

	"github.com/gojue/ecapture/internal/probe/base/handlers"
)

func TestMasterSecretEvent_Validate_DTLS12(t *testing.T) {
	event := &MasterSecretEvent{
		Version: handlers.Dtls12Version,
	}
	for i := range event.ClientRandom {
		event.ClientRandom[i] = byte(i + 1)
	}

	if err := event.Validate(); err != nil {
		t.Fatalf("Validate() returned error for DTLS 1.2: %v", err)
	}
}

func TestMasterSecretEvent_Validate_InvalidVersion(t *testing.T) {
	event := &MasterSecretEvent{
		Version: 0x9999,
	}
	for i := range event.ClientRandom {
		event.ClientRandom[i] = byte(i + 1)
	}

	if err := event.Validate(); err == nil {
		t.Fatal("Validate() should reject unknown version")
	}
}
