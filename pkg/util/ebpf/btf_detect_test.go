// Copyright 2022 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.

package ebpf

import (
	"testing"

	"github.com/gojue/ecapture/internal/config"
)

func TestIsEnableBTF_Runtime(t *testing.T) {
	enabled, err := IsEnableBTF()
	t.Logf("IsEnableBTF: enabled=%v err=%v", enabled, err)
}

func TestUseCoreBTF_AutoDetect_Runtime(t *testing.T) {
	core, err := UseCoreBTF(config.BTFModeAutoDetect)
	t.Logf("UseCoreBTF auto: core=%v err=%v", core, err)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !core {
		t.Fatalf("expected core=true on system with BTF, got false")
	}
}
