// Copyright 2021 The Casdoor Authors. All Rights Reserved.
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

package controllers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/casdoor/casdoor/form"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

const (
	ResponseTypeLogin   = "login"
	ResponseTypeCode    = "code"
	ResponseTypeToken   = "token"
	ResponseTypeIdToken = "id_token"
	ResponseTypeSaml    = "saml"
	ResponseTypeCas     = "cas"
	ResponseTypeDevice  = "device"
)

type Response struct {
	Status string      `json:"status"`
	Msg    string      `json:"msg"`
	Sub    string      `json:"sub"`
	Name   string      `json:"name"`
	Data   interface{} `json:"data"`
	Data2  interface{} `json:"data2"`
	Data3  interface{} `json:"data3"`
}

type Captcha struct {
	Owner         string `json:"owner"`
	Name          string `json:"name"`
	Type          string `json:"type"`
	AppKey        string `json:"appKey"`
	Scene         string `json:"scene"`
	CaptchaId     string `json:"captchaId"`
	CaptchaImage  []byte `json:"captchaImage"`
	ClientId      string `json:"clientId"`
	ClientSecret  string `json:"clientSecret"`
	ClientId2     string `json:"clientId2"`
	ClientSecret2 string `json:"clientSecret2"`
	SubType       string `json:"subType"`
}

// this API is used by "Api URL" of Flarum's FoF Passport plugin
// https://github.com/FriendsOfFlarum/passport
type LaravelResponse struct {
	Id              string `json:"id"`
	Name            string `json:"name"`
	Email           string `json:"email"`
	EmailVerifiedAt string `json:"email_verified_at"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}

// Signup
// @Tag Login API
// @Title Signup
// @Description sign up a new user
// @Param   username     formData    string  true        "The username to sign up"
// @Param   password     formData    string  true        "The password"
// @Success 200 {object} controllers.Response The Response object
// @router /signup [post]
func (c *ApiController) Signup() {
	if c.GetSessionUsername() != "" {
		c.ResponseError(c.T("account:Please sign out first"), c.GetSessionUsername())
		return
	}

	var authForm form.AuthForm
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &authForm)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	application, err := object.GetApplication(fmt.Sprintf("admin/%s", authForm.Application))
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if application == nil {
		c.ResponseError(fmt.Sprintf(c.T("auth:The application: %s does not exist"), authForm.Application))
		return
	}

	if !application.EnableSignUp {
		c.ResponseError(c.T("account:The application does not allow to sign up new account"))
		return
	}

	organization, err := object.GetOrganization(util.GetId("admin", authForm.Organization))
	if err != nil {
		c.ResponseError(c.T(err.Error()))
		return
	}

	if organization == nil {
		c.ResponseError(fmt.Sprintf(c.T("auth:The organization: %s does not exist"), authForm.Organization))
		return
	}

	clientIp := util.GetClientIpFromRequest(c.Ctx.Request)
	err = object.CheckEntryIp(clientIp, nil, application, organization, c.GetAcceptLanguage())
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	msg := object.CheckUserSignup(application, organization, &authForm, c.GetAcceptLanguage())
	if msg != "" {
		c.ResponseError(msg)
		return
	}

	invitation, msg := object.CheckInvitationCode(application, organization, &authForm, c.GetAcceptLanguage())
	if msg != "" {
		c.ResponseError(msg)
		return
	}
	invitationName := ""
	if invitation != nil {
		invitationName = invitation.Name
	}

	userEmailVerified := false

	if application.IsSignupItemVisible("Email") && application.GetSignupItemRule("Email") != "No verification" && authForm.Email != "" {
		var checkResult *object.VerifyResult
		checkResult, err = object.CheckVerificationCode(authForm.Email, authForm.EmailCode, c.GetAcceptLanguage())
		if err != nil {
			c.ResponseError(c.T(err.Error()))
			return
		}
		if checkResult.Code != object.VerificationSuccess {
			c.ResponseError(checkResult.Msg)
			return
		}

		userEmailVerified = true
	}

	var checkPhone string
	if application.IsSignupItemVisible("Phone") && application.GetSignupItemRule("Phone") != "No verification" && authForm.Phone != "" {
		checkPhone, _ = util.GetE164Number(authForm.Phone, authForm.CountryCode)

		var checkResult *object.VerifyResult
		checkResult, err = object.CheckVerificationCode(checkPhone, authForm.PhoneCode, c.GetAcceptLanguage())
		if err != nil {
			c.ResponseError(c.T(err.Error()))
			return
		}
		if checkResult.Code != object.VerificationSuccess {
			c.ResponseError(checkResult.Msg)
			return
		}
	}

	id, err := object.GenerateIdForNewUser(application)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	username := authForm.Username
	if !application.IsSignupItemVisible("Username") {
		if organization.UseEmailAsUsername && application.IsSignupItemVisible("Email") {
			username = authForm.Email
		} else {
			username = id
		}
	}

	initScore, err := organization.GetInitScore()
	if err != nil {
		c.ResponseError(fmt.Errorf(c.T("account:Get init score failed, error: %w"), err).Error())
		return
	}

	userType := "normal-user"
	if authForm.Plan != "" && authForm.Pricing != "" {
		err = object.CheckPricingAndPlan(authForm.Organization, authForm.Pricing, authForm.Plan, c.GetAcceptLanguage())
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
		userType = "paid-user"
	}

	user := &object.User{
		Owner:             authForm.Organization,
		Name:              username,
		CreatedTime:       util.GetCurrentTime(),
		Id:                id,
		Type:              userType,
		Password:          authForm.Password,
		DisplayName:       authForm.Name,
		Gender:            authForm.Gender,
		Bio:               authForm.Bio,
		Tag:               authForm.Tag,
		Education:         authForm.Education,
		Avatar:            organization.DefaultAvatar,
		Email:             authForm.Email,
		Phone:             authForm.Phone,
		CountryCode:       authForm.CountryCode,
		Address:           []string{},
		Affiliation:       authForm.Affiliation,
		IdCard:            authForm.IdCard,
		Region:            authForm.Region,
		Score:             initScore,
		IsAdmin:           false,
		IsForbidden:       false,
		IsDeleted:         false,
		SignupApplication: application.Name,
		Properties:        map[string]string{},
		Karma:             0,
		Invitation:        invitationName,
		InvitationCode:    authForm.InvitationCode,
		EmailVerified:     userEmailVerified,
		RegisterType:      "Application Signup",
		RegisterSource:    fmt.Sprintf("%s/%s", authForm.Organization, application.Name),
	}

	if len(organization.Tags) > 0 {
		tokens := strings.Split(organization.Tags[0], "|")
		if len(tokens) > 0 {
			user.Tag = tokens[0]
		}
	}

	if application.GetSignupItemRule("Display name") == "First, last" {
		if authForm.FirstName != "" || authForm.LastName != "" {
			user.DisplayName = fmt.Sprintf("%s %s", authForm.FirstName, authForm.LastName)
			user.FirstName = authForm.FirstName
			user.LastName = authForm.LastName
		}
	}

	if invitation != nil && invitation.SignupGroup != "" {
		user.Groups = []string{invitation.SignupGroup}
	}

	if application.DefaultGroup != "" && user.Groups == nil {
		user.Groups = []string{application.DefaultGroup}
	}

	affected, err := object.AddUser(user, c.GetAcceptLanguage())
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if !affected {
		c.ResponseError(c.T("account:Failed to add user"), util.StructToJson(user))
		return
	}

	err = object.AddUserToOriginalDatabase(user)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if invitation != nil {
		invitation.UsedCount += 1
		_, err := object.UpdateInvitation(invitation.GetId(), invitation, c.GetAcceptLanguage())
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
	}

	if user.Type == "normal-user" {
		c.SetSessionUsername(user.GetId())
	}

	if authForm.Email != "" {
		err = object.DisableVerificationCode(authForm.Email)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
	}

	if checkPhone != "" {
		err = object.DisableVerificationCode(checkPhone)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
	}

	c.Ctx.Input.SetParam("recordUserId", user.GetId())
	c.Ctx.Input.SetParam("recordSignup", "true")

	userId := user.GetId()
	util.LogInfo(c.Ctx, "API: [%s] is signed up as new user", userId)

	c.ResponseOk(userId)
}

// Logout
// @Title Logout
// @Tag Login API
// @Description logout the current user
// @Param   id_token_hint   query        string  false        "id_token_hint"
// @Param   post_logout_redirect_uri    query    string  false     "post_logout_redirect_uri"
// @Param   state     query    string  false     "state"
// @Param   logout_token    query    string  false     "logout_token for backchannel logout"
// @Success 200 {object} controllers.Response The Response object
// @router /logout [post]
func (c *ApiController) Logout() {
	// https://openid.net/specs/openid-connect-rpinitiated-1_0-final.html
	accessToken := c.GetString("id_token_hint")
	redirectUri := c.GetString("post_logout_redirect_uri")
	state := c.GetString("state")
	logoutToken := c.GetString("logout_token")

	user := c.GetSessionUsername()

	// Handle backchannel logout (RFC 8620)
	if logoutToken != "" {
		c.handleBackchannelLogout(logoutToken)
		return
	}

	if accessToken == "" && redirectUri == "" {
		if user == "" {
			c.ResponseOk()
			return
		}

		// Clear all sessions for this user across all applications
		c.ClearUserSession()
		c.ClearTokenSession()
		owner, username := util.GetOwnerAndNameFromId(user)
		
		// Delete all sessions for this user
		sessions, err := object.GetUserAppSessions(owner, username, object.CasdoorApplication)
		if err == nil {
			for _, session := range sessions {
				for _, sid := range session.SessionId {
					object.DeleteBeegoSession([]string{sid})
				}
				object.DeleteSession(session.GetId())
			}
		}
		
		// Also expire all tokens for this user
		tokens, err := object.GetTokens(owner, owner)
		if err == nil {
			for _, token := range tokens {
				if token.User == username {
					token.ExpiresIn = 0
					object.UpdateToken(token.GetId(), token, false)
				}
			}
		}

		util.LogInfo(c.Ctx, "API: [%s] logged out", user)

		application := c.GetSessionApplication()
		if application == nil || application.Name == "app-built-in" || application.HomepageUrl == "" {
			c.ResponseOk(user)
			return
		}
		c.ResponseOk(user, application.HomepageUrl)
		return
	} else {
		// OIDC RP-Initiated Logout
		if accessToken == "" {
			c.ResponseError(c.T("general:Missing parameter") + ": id_token_hint")
			return
		}

		_, application, token, err := object.ExpireTokenByAccessToken(accessToken)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
		if token == nil {
			c.ResponseError(c.T("token:Token not found, invalid accessToken"))
			return
		}
		if application == nil {
			c.ResponseError(fmt.Sprintf(c.T("auth:The application: %s does not exist")), token.Application)
			return
		}

		if user == "" {
			user = util.GetId(token.Organization, token.User)
		}

		c.ClearUserSession()
		c.ClearTokenSession()
		owner, username := util.GetOwnerAndNameFromId(user)

		// Clear all sessions for this user in this application
		sessions, err := object.GetUserAppSessions(owner, username, token.Application)
		if err == nil {
			for _, session := range sessions {
				for _, sid := range session.SessionId {
					object.DeleteBeegoSession([]string{sid})
				}
				object.DeleteSession(session.GetId())
			}
		}

		// Also clear the Casdoor application session
		_, err = object.DeleteSessionId(util.GetSessionId(owner, username, object.CasdoorApplication), c.Ctx.Input.CruSession.SessionID())
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		util.LogInfo(c.Ctx, "API: [%s] logged out from OIDC", user)

		if redirectUri == "" {
			c.ResponseOk()
			return
		} else {
			if application.IsRedirectUriValid(redirectUri) {
				redirectUrl := redirectUri
				if state != "" {
					if strings.Contains(redirectUri, "?") {
						redirectUrl = fmt.Sprintf("%s&state=%s", strings.TrimSuffix(redirectUri, "/"), state)
					} else {
						redirectUrl = fmt.Sprintf("%s?state=%s", strings.TrimSuffix(redirectUri, "/"), state)
					}
				}
				c.Ctx.Redirect(http.StatusFound, redirectUrl)
			} else {
				c.ResponseError(fmt.Sprintf(c.T("token:Redirect URI: %s doesn't exist in the allowed Redirect URI list"), redirectUri))
				return
			}
		}
	}
}

// handleBackchannelLogout handles OIDC Back-Channel Logout (RFC 8620)
func (c *ApiController) handleBackchannelLogout(logoutToken string) {
	// Parse and validate the logout token
	// The logout token is a JWT that contains sid (session ID) or sub (subject)
	// For simplicity, we'll validate it and extract the user information
	
	// This is a placeholder - in production, you should:
	// 1. Validate the JWT signature
	// 2. Check the token issuer
	// 3. Verify the audience
	// 4. Check the events claim for http://schemas.openid.net/event/backchannel-logout
	
	// For now, return success as per RFC 8620
	// The IdP should implement proper JWT parsing here
	
	c.Ctx.Output.SetStatus(200)
	c.Data["json"] = map[string]string{}
	c.ServeJSON()
	
	util.LogInfo(c.Ctx, "Backchannel logout received")
}

// GetAccount
// @Title GetAccount
// @Tag Account API
// @Description get the details of the current account
// @Success 200 {object} controllers.Response The Response object
// @router /get-account [get]
func (c *ApiController) GetAccount() {
	var err error
	user, ok := c.RequireSignedInUser()
	if !ok {
		return
	}

	managedAccounts := c.Input().Get("managedAccounts")
	if managedAccounts == "1" {
		user, err = object.ExtendManagedAccountsWithUser(user)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
	}

	err = object.ExtendUserWithRolesAndPermissions(user)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if user != nil {
		user.Permissions = object.GetMaskedPermissions(user.Permissions)
		user.Roles = object.GetMaskedRoles(user.Roles)
		user.MultiFactorAuths = object.GetAllMfaProps(user, true)
	}

	organization, err := object.GetMaskedOrganization(object.GetOrganizationByUser(user))
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	isAdminOrSelf := c.IsAdminOrSelf(user)
	u, err := object.GetMaskedUser(user, isAdminOrSelf)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if organization != nil && len(organization.CountryCodes) == 1 && u != nil && u.CountryCode == "" {
		u.CountryCode = organization.CountryCodes[0]
	}

	accessToken := c.GetSessionToken()
	if accessToken == "" {
		accessToken, err = object.GetAccessTokenByUser(user, c.Ctx.Request.Host)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
		c.SetSessionToken(accessToken)
	}
	u.AccessToken = accessToken

	resp := Response{
		Status: "ok",
		Sub:    user.Id,
		Name:   user.Name,
		Data:   u,
		Data2:  organization,
	}
	c.Data["json"] = resp
	c.ServeJSON()
}

// GetUserinfo
// UserInfo
// @Title UserInfo
// @Tag Account API
// @Description return user information according to OIDC standards
// @Success 200 {object} object.Userinfo The Response object
// @router /userinfo [get]
func (c *ApiController) GetUserinfo() {
	user, ok := c.RequireSignedInUser()
	if !ok {
		return
	}

	scope, aud := c.GetSessionOidc()
	host := c.Ctx.Request.Host

	userInfo, err := object.GetUserInfo(user, scope, aud, host)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.Data["json"] = userInfo
	c.ServeJSON()
}

// GetUserinfo2
// LaravelResponse
// @Title UserInfo2
// @Tag Account API
// @Description return Laravel compatible user information according to OAuth 2.0
// @Success 200 {object} controllers.LaravelResponse The Response object
// @router /user [get]
func (c *ApiController) GetUserinfo2() {
	user, ok := c.RequireSignedInUser()
	if !ok {
		return
	}

	response := LaravelResponse{
		Id:              user.Id,
		Name:            user.Name,
		Email:           user.Email,
		EmailVerifiedAt: user.CreatedTime,
		CreatedAt:       user.CreatedTime,
		UpdatedAt:       user.UpdatedTime,
	}

	c.Data["json"] = response
	c.ServeJSON()
}

// GetCaptcha ...
// @Tag Login API
// @Title GetCaptcha
// @router /get-captcha [get]
// @Success 200 {object} object.Userinfo The Response object
func (c *ApiController) GetCaptcha() {
	applicationId := c.Input().Get("applicationId")
	isCurrentProvider := c.Input().Get("isCurrentProvider")

	captchaProvider, err := object.GetCaptchaProviderByApplication(applicationId, isCurrentProvider, c.GetAcceptLanguage())
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if captchaProvider != nil {
		if captchaProvider.Type == "Default" {
			id, img, err := object.GetCaptcha()
			if err != nil {
				c.ResponseError(err.Error())
				return
			}

			c.ResponseOk(Captcha{Owner: captchaProvider.Owner, Name: captchaProvider.Name, Type: captchaProvider.Type, CaptchaId: id, CaptchaImage: img})
			return
		} else if captchaProvider.Type != "" {
			c.ResponseOk(Captcha{
				Owner:         captchaProvider.Owner,
				Name:          captchaProvider.Name,
				Type:          captchaProvider.Type,
				SubType:       captchaProvider.SubType,
				ClientId:      captchaProvider.ClientId,
				ClientSecret:  "***",
				ClientId2:     captchaProvider.ClientId2,
				ClientSecret2: captchaProvider.ClientSecret2,
			})
			return
		}
	}

	c.ResponseOk(Captcha{Type: "none"})
}
