// Copyright 2026 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package object

import (
	"encoding/json"
	"testing"
)

func TestIdTokenClaimsCarrySid(t *testing.T) {
	const sid = "session-hash"
	claims := Claims{User: &User{Owner: "org", Name: "alice"}, TokenType: "id-token"}
	claims.Sid = sid

	formats := map[string]interface{}{
		"JWT":          claims,
		"JWT-Empty":    getShortClaims(claims),
		"JWT-Standard": getStandardClaims(claims),
		"JWT-Custom":   getClaimsCustom(claims, nil, nil),
	}

	for format, formatClaims := range formats {
		payload, err := json.Marshal(formatClaims)
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}

		var decoded map[string]interface{}
		if err = json.Unmarshal(payload, &decoded); err != nil {
			t.Fatalf("%s: %v", format, err)
		}

		if decoded["sid"] != sid {
			t.Errorf("%s: sid = %v, want %q", format, decoded["sid"], sid)
		}
	}
}
