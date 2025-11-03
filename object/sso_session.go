// Copyright 2025 The Casdoor Authors. All Rights Reserved.
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
	"fmt"

	"github.com/casdoor/casdoor/util"
	"github.com/xorm-io/core"
)

// SsoSession persists federated single sign-on session metadata so that
// Casdoor can perform protocol specific Single Logout (SLO) operations.
type SsoSession struct {
	Owner       string `xorm:"varchar(100) notnull pk" json:"owner"`
	Name        string `xorm:"varchar(100) notnull pk" json:"name"`
	Application string `xorm:"varchar(100) notnull pk" json:"application"`
	SessionId   string `xorm:"varchar(100) notnull pk" json:"sessionId"`

	CreatedTime string `xorm:"varchar(100)" json:"createdTime"`
	UpdatedTime string `xorm:"varchar(100)" json:"updatedTime"`

	Protocol string `xorm:"varchar(32)" json:"protocol"`
	ClientId string `xorm:"varchar(100)" json:"clientId"`
	Sid      string `xorm:"varchar(128)" json:"sid"`

	SessionIndex string `xorm:"varchar(128)" json:"sessionIndex"`
	NameId       string `xorm:"varchar(256)" json:"nameId"`
	ServiceUrl   string `xorm:"varchar(512)" json:"serviceUrl"`
	RelayState   string `xorm:"varchar(512)" json:"relayState"`

	FrontchannelLogoutUri             string `xorm:"varchar(512)" json:"frontchannelLogoutUri"`
	FrontchannelLogoutSessionRequired bool   `json:"frontchannelLogoutSessionRequired"`
	BackchannelLogoutUri              string `xorm:"varchar(512)" json:"backchannelLogoutUri"`
	BackchannelLogoutSessionRequired  bool   `json:"backchannelLogoutSessionRequired"`
	PostLogoutRedirectUri             string `xorm:"varchar(512)" json:"postLogoutRedirectUri"`
}

// GetId returns the composite identifier for the SSO session.
func (s *SsoSession) GetId() string {
	return fmt.Sprintf("%s/%s/%s/%s", s.Owner, s.Name, s.Application, s.SessionId)
}

func addSsoSession(session *SsoSession) (bool, error) {
	session.CreatedTime = util.GetCurrentTime()
	session.UpdatedTime = session.CreatedTime
	affected, err := ormer.Engine.Insert(session)
	if err != nil {
		return false, err
	}
	return affected != 0, nil
}

// AddOrUpdateSsoSession creates a new federated session record or overwrites the
// existing one with fresh metadata.
func AddOrUpdateSsoSession(session *SsoSession) (bool, error) {
	if session == nil {
		return false, fmt.Errorf("session is nil")
	}

	existing := &SsoSession{}
	has, err := ormer.Engine.ID(core.PK{session.Owner, session.Name, session.Application, session.SessionId}).Get(existing)
	if err != nil {
		return false, err
	}

	session.UpdatedTime = util.GetCurrentTime()

	if !has {
		return addSsoSession(session)
	}

	// preserve original creation timestamp
	session.CreatedTime = existing.CreatedTime
	affected, err := ormer.Engine.ID(core.PK{session.Owner, session.Name, session.Application, session.SessionId}).AllCols().Update(session)
	if err != nil {
		return false, err
	}
	return affected != 0, nil
}

// GetSsoSessionsBySessionId returns all federated sessions bound to a specific
// Casdoor HTTP session id.
func GetSsoSessionsBySessionId(sessionId string) ([]*SsoSession, error) {
	sessions := []*SsoSession{}
	err := ormer.Engine.Where("session_id = ?", sessionId).Find(&sessions)
	if err != nil {
		return nil, err
	}
	return sessions, nil
}

// GetSsoSessionsByUser returns all SSO sessions for a user regardless of
// browser session.
func GetSsoSessionsByUser(owner, name string) ([]*SsoSession, error) {
	sessions := []*SsoSession{}
	err := ormer.Engine.Where("owner = ? and name = ?", owner, name).Find(&sessions)
	if err != nil {
		return nil, err
	}
	return sessions, nil
}

// GetSsoSessionsByUserAndApp returns federated sessions for the given user and application.
func GetSsoSessionsByUserAndApp(owner, name, application string) ([]*SsoSession, error) {
	sessions := []*SsoSession{}
	err := ormer.Engine.Where("owner = ? and name = ? and application = ?", owner, name, application).Find(&sessions)
	if err != nil {
		return nil, err
	}
	return sessions, nil
}

// DeleteSsoSession removes a single federated session entry.
func DeleteSsoSession(session *SsoSession) (bool, error) {
	if session == nil {
		return false, nil
	}

	affected, err := ormer.Engine.ID(core.PK{session.Owner, session.Name, session.Application, session.SessionId}).Delete(&SsoSession{})
	if err != nil {
		return false, err
	}
	return affected != 0, nil
}

// DeleteSsoSessionsBySessionId removes all federated sessions associated with
// the provided HTTP session id.
func DeleteSsoSessionsBySessionId(sessionId string) error {
	if sessionId == "" {
		return nil
	}

	_, err := ormer.Engine.Where("session_id = ?", sessionId).Delete(&SsoSession{})
	return err
}

// DeleteSsoSessionsByUser removes all federated sessions for the specified user.
func DeleteSsoSessionsByUser(owner, name string) error {
	if owner == "" || name == "" {
		return nil
	}

	_, err := ormer.Engine.Where("owner = ? and name = ?", owner, name).Delete(&SsoSession{})
	return err
}
