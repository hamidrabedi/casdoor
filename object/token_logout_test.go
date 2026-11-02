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

import "testing"

func TestFilterTokensBySessionId(t *testing.T) {
	tokens := []*Token{
		{Name: "a-1", SessionId: "a"},
		{Name: "b-1", SessionId: "b"},
		{Name: "a-2", SessionId: "a"},
		{Name: "none"},
	}

	got := filterTokensBySessionId(tokens, "a")
	if len(got) != 2 || got[0].Name != "a-1" || got[1].Name != "a-2" {
		t.Errorf("unexpected tokens: %v", got)
	}

	if got = filterTokensBySessionId(tokens, "missing"); len(got) != 0 {
		t.Errorf("unexpected tokens: %v", got)
	}
}
