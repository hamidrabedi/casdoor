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

const (
	SloTypeOidc  = "oidc"
	SloTypeSaml  = "saml"
	SloTypeCas   = "cas"
	SloTypeOAuth = "oauth2"
)

// SloSession stores protocol-specific session metadata that is required to
// propagate single logout (SLO) notifications to relying parties.
type SloSession struct {
	Owner       string `xorm:"varchar(100) notnull pk" json:"owner"`
	Name        string `xorm:"varchar(100) notnull pk" json:"name"`
	Application string `xorm:"varchar(100) notnull pk" json:"application"`
	Type        string `xorm:"varchar(20) notnull pk" json:"type"`
	SessionKey  string `xorm:"varchar(200) notnull pk" json:"sessionKey"`

	CreatedTime           string            `xorm:"varchar(100)" json:"createdTime"`
	ClientId              string            `xorm:"varchar(100) index" json:"clientId"`
	Sid                   string            `xorm:"varchar(200) index" json:"sid"`
	SessionId             string            `xorm:"varchar(200) index" json:"sessionId"`
	SessionIndex          string            `xorm:"varchar(200) index" json:"sessionIndex"`
	SessionState          string            `xorm:"varchar(200)" json:"sessionState"`
	NameId                string            `xorm:"varchar(200)" json:"nameId"`
	Service               string            `xorm:"varchar(500)" json:"service"`
	LogoutUri             string            `xorm:"varchar(500)" json:"logoutUri"`
	FrontChannelLogoutUri string            `xorm:"varchar(500)" json:"frontChannelLogoutUri"`
	BackChannelLogoutUri  string            `xorm:"varchar(500)" json:"backChannelLogoutUri"`
	TokenName             string            `xorm:"varchar(100) index" json:"tokenName"`
	Extra                 map[string]string `xorm:"json" json:"extra"`
}

// GetId returns the composite identifier of the SLO session record.
func (session *SloSession) GetId() string {
	return fmt.Sprintf("%s/%s/%s/%s/%s", session.Owner, session.Name, session.Application, session.Type, session.SessionKey)
}

func (session *SloSession) ensureDefaults() {
	if session.CreatedTime == "" {
		session.CreatedTime = util.GetCurrentTime()
	}
	if session.Extra == nil {
		session.Extra = map[string]string{}
	}
}

// GetSloSession fetches a specific SLO session entry.
func GetSloSession(owner, name, application, typ, sessionKey string) (*SloSession, error) {
	if owner == "" || name == "" || application == "" || typ == "" || sessionKey == "" {
		return nil, nil
	}

	session := SloSession{
		Owner:       owner,
		Name:        name,
		Application: application,
		Type:        typ,
		SessionKey:  sessionKey,
	}

	existed, err := ormer.Engine.Get(&session)
	if err != nil {
		return nil, err
	}
	if !existed {
		return nil, nil
	}
	return &session, nil
}

// AddSloSession inserts or updates an SLO session record.
func AddSloSession(session *SloSession) (bool, error) {
	if session == nil {
		return false, nil
	}

	session.ensureDefaults()

	existing, err := GetSloSession(session.Owner, session.Name, session.Application, session.Type, session.SessionKey)
	if err != nil {
		return false, err
	}

	if existing == nil {
		affected, err := ormer.Engine.Insert(session)
		if err != nil {
			return false, err
		}
		return affected != 0, nil
	}

	// Preserve original creation time if the caller did not override it.
	if session.CreatedTime == "" {
		session.CreatedTime = existing.CreatedTime
	}

	affected, err := ormer.Engine.ID(core.PK{session.Owner, session.Name, session.Application, session.Type, session.SessionKey}).AllCols().Update(session)
	if err != nil {
		return false, err
	}
	return affected != 0, nil
}

// DeleteSloSession removes a specific SLO session entry.
func DeleteSloSession(owner, name, application, typ, sessionKey string) (bool, error) {
	affected, err := ormer.Engine.ID(core.PK{owner, name, application, typ, sessionKey}).Delete(&SloSession{})
	if err != nil {
		return false, err
	}
	return affected != 0, nil
}

// DeleteSloSessionsByToken removes all sessions that were minted from the given token name.
func DeleteSloSessionsByToken(tokenName string) (int64, error) {
	if tokenName == "" {
		return 0, nil
	}
	return ormer.Engine.Where("token_name = ?", tokenName).Delete(&SloSession{})
}

// DeleteSloSessionsByUser removes all SLO sessions for a given user.
func DeleteSloSessionsByUser(owner, name string) (int64, error) {
	if owner == "" || name == "" {
		return 0, nil
	}
	return ormer.Engine.Where("owner = ? AND name = ?", owner, name).Delete(&SloSession{})
}

// GetSloSessionsByUser returns every SLO session associated with the user.
func GetSloSessionsByUser(owner, name string) ([]*SloSession, error) {
	sessions := []*SloSession{}
	if owner == "" || name == "" {
		return sessions, nil
	}

	err := ormer.Engine.Where("owner = ? AND name = ?", owner, name).Find(&sessions)
	return sessions, err
}

// GetSloSessionsByToken lists SLO sessions linked to the supplied token name.
func GetSloSessionsByToken(tokenName string) ([]*SloSession, error) {
	sessions := []*SloSession{}
	if tokenName == "" {
		return sessions, nil
	}

	err := ormer.Engine.Where("token_name = ?", tokenName).Find(&sessions)
	return sessions, err
}

// GetSloSessionsBySid lists SLO sessions that share the provided OIDC session identifier.
func GetSloSessionsBySid(sid string) ([]*SloSession, error) {
	sessions := []*SloSession{}
	if sid == "" {
		return sessions, nil
	}

	err := ormer.Engine.Where("sid = ?", sid).Find(&sessions)
	return sessions, err
}

// GetSloSessionsBySessionId locates SLO sessions associated with the underlying Casdoor session id.
func GetSloSessionsBySessionId(sessionId string) ([]*SloSession, error) {
	sessions := []*SloSession{}
	if sessionId == "" {
		return sessions, nil
	}

	err := ormer.Engine.Where("session_id = ?", sessionId).Find(&sessions)
	return sessions, err
}

func buildOidcSloSession(application *Application, user *User, token *Token, redirectUri string, sessionId string) *SloSession {
	if application == nil || user == nil || token == nil {
		return nil
	}

	sessionKey := token.Sid
	if sessionKey == "" {
		sessionKey = token.Name
	}

	session := &SloSession{
		Owner:                 user.Owner,
		Name:                  user.Name,
		Application:           application.GetId(),
		Type:                  SloTypeOidc,
		SessionKey:            sessionKey,
		ClientId:              application.ClientId,
		Sid:                   token.Sid,
		SessionId:             sessionId,
		SessionState:          token.SessionState,
		TokenName:             token.Name,
		LogoutUri:             application.LogoutUrl,
		FrontChannelLogoutUri: application.FrontChannelLogoutUri,
		BackChannelLogoutUri:  application.BackChannelLogoutUri,
		Service:               redirectUri,
	}

	if redirectUri != "" {
		session.Extra = map[string]string{"redirect_uri": redirectUri}
	}

	return session
}

func AddOidcSloSession(application *Application, user *User, token *Token, redirectUri string, sessionId string) (bool, error) {
	session := buildOidcSloSession(application, user, token, redirectUri, sessionId)
	if session == nil {
		return false, nil
	}
	return AddSloSession(session)
}
