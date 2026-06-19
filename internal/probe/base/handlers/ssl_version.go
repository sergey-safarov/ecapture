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

import "fmt"

// SSL/TLS/DTLS protocol version constants (OpenSSL ssl_local.h).
const (
	Tls10Version  int32 = 0x0301
	Tls11Version  int32 = 0x0302
	Tls12Version  int32 = 0x0303
	Tls13Version  int32 = 0x0304
	Dtls10Version int32 = 0xFEFF
	Dtls12Version int32 = 0xFEFD
	Dtls13Version int32 = 0xFEFC
)

// IsValidSSLVersion reports whether version is a known TLS or DTLS protocol version.
func IsValidSSLVersion(version int32) bool {
	switch version {
	case Tls10Version, Tls11Version, Tls12Version, Tls13Version,
		Dtls10Version, Dtls12Version, Dtls13Version:
		return true
	default:
		return false
	}
}

// UsesMasterSecretKeylog reports whether the version exports keys via CLIENT_RANDOM
// (TLS 1.2 and earlier, DTLS 1.0/1.2). Wireshark uses the same NSS key log format
// for DTLS 1.2 master secrets as for TLS 1.2.
func UsesMasterSecretKeylog(version int32) bool {
	switch version {
	case Tls10Version, Tls11Version, Tls12Version,
		Dtls10Version, Dtls12Version:
		return true
	default:
		return false
	}
}

// UsesTLS13Keylog reports whether the version exports TLS 1.3-style traffic secrets.
func UsesTLS13Keylog(version int32) bool {
	return version == Tls13Version || version == Dtls13Version
}

// SSLVersionString returns a human-readable name for a TLS/DTLS version.
func SSLVersionString(version int32) string {
	switch version {
	case Tls10Version:
		return "TLS 1.0"
	case Tls11Version:
		return "TLS 1.1"
	case Tls12Version:
		return "TLS 1.2"
	case Tls13Version:
		return "TLS 1.3"
	case Dtls10Version:
		return "DTLS 1.0"
	case Dtls12Version:
		return "DTLS 1.2"
	case Dtls13Version:
		return "DTLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}
