// Copyright 2022 The Casdoor Authors. All Rights Reserved.
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
	"fmt"
	"net/http"
	"net/url"

	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

func (c *ApiController) GetSamlMeta() {
	host := c.Ctx.Request.Host
	paramApp := c.Input().Get("application")
	application, err := object.GetApplication(paramApp)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if application == nil {
		c.ResponseError(fmt.Sprintf(c.T("saml:Application %s not found"), paramApp))
		return
	}

	enablePostBinding, err := c.GetBool("enablePostBinding", false)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	metadata, err := object.GetSamlMeta(application, host, enablePostBinding)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.Data["xml"] = metadata
	c.ServeXML()
}

func (c *ApiController) HandleSamlRedirect() {
	host := c.Ctx.Request.Host

	owner := c.Ctx.Input.Param(":owner")
	application := c.Ctx.Input.Param(":application")

	relayState := c.Input().Get("RelayState")
	samlRequest := c.Input().Get("SAMLRequest")
	username := c.Input().Get("username")
	loginHint := c.Input().Get("login_hint")

	targetURL := object.GetSamlRedirectAddress(owner, application, relayState, samlRequest, host, username, loginHint)

	c.Redirect(targetURL, http.StatusSeeOther)
}

// HandleSamlLogout handles SAML Single Logout requests
// @Title HandleSamlLogout
// @Tag SAML API
// @Description Handle SAML Single Logout request
// @Param   owner     path    string  true        "The owner of application"
// @Param   application    path    string  true        "The name of application"
// @Param   SAMLRequest    query    string  false       "SAML Logout Request"
// @Param   SAMLResponse   query    string  false       "SAML Logout Response"
// @Success 200 {object} controllers.Response The Response object
// @router /api/saml/logout/:owner/:application [get,post]
func (c *ApiController) HandleSamlLogout() {
	host := c.Ctx.Request.Host
	owner := c.Ctx.Input.Param(":owner")
	applicationName := c.Ctx.Input.Param(":application")

	samlRequest := c.Input().Get("SAMLRequest")
	samlResponse := c.Input().Get("SAMLResponse")
	relayState := c.Input().Get("RelayState")

	application, err := object.GetApplication(fmt.Sprintf("%s/%s", owner, applicationName))
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if application == nil {
		c.ResponseError(fmt.Sprintf(c.T("auth:The application: %s does not exist"), applicationName))
		return
	}

	// Handle incoming logout request from IDP
	if samlRequest != "" {
		// Parse the SAML logout request
		// For IDP-initiated logout, we need to logout the user and send a response back
		userId := c.GetSessionUsername()
		if userId != "" {
			c.ClearUserSession()
			c.ClearTokenSession()
			owner, username := util.GetOwnerAndNameFromId(userId)
			_, err := object.DeleteSessionId(util.GetSessionId(owner, username, object.CasdoorApplication), c.Ctx.Input.CruSession.SessionID())
			if err != nil {
				c.ResponseError(err.Error())
				return
			}
			util.LogInfo(c.Ctx, "API: [%s] logged out via SAML SLO", userId)
		}

		// Generate and return SAML logout response
		logoutResponse, destination, err := object.GetSamlLogoutResponse(application, host, "", "")
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		// Redirect back to the IDP with the logout response
		if destination != "" {
			redirectUrl := fmt.Sprintf("%s?SAMLResponse=%s", destination, url.QueryEscape(logoutResponse))
			if relayState != "" {
				redirectUrl += fmt.Sprintf("&RelayState=%s", url.QueryEscape(relayState))
			}
			c.Redirect(redirectUrl, http.StatusSeeOther)
		} else {
			c.ResponseOk(logoutResponse)
		}
		return
	}

	// Handle incoming logout response from IDP
	if samlResponse != "" {
		// Parse the SAML logout response
		// This is the response to our SP-initiated logout request
		userId := c.GetSessionUsername()
		if userId != "" {
			c.ClearUserSession()
			c.ClearTokenSession()
			owner, username := util.GetOwnerAndNameFromId(userId)
			_, err := object.DeleteSessionId(util.GetSessionId(owner, username, object.CasdoorApplication), c.Ctx.Input.CruSession.SessionID())
			if err != nil {
				c.ResponseError(err.Error())
				return
			}
			util.LogInfo(c.Ctx, "API: [%s] logged out via SAML SLO", userId)
		}

		// Redirect to application homepage or relay state
		if relayState != "" {
			c.Redirect(relayState, http.StatusSeeOther)
		} else if application.HomepageUrl != "" {
			c.Redirect(application.HomepageUrl, http.StatusSeeOther)
		} else {
			c.ResponseOk("Logout successful")
		}
		return
	}

	c.ResponseError("Missing SAMLRequest or SAMLResponse parameter")
}

// InitiateSamlLogout initiates SAML Single Logout from this IDP
// @Title InitiateSamlLogout
// @Tag SAML API
// @Description Initiate SAML Single Logout
// @Param   owner     path    string  true        "The owner of application"
// @Param   application    path    string  true        "The name of application"
// @Success 200 {object} controllers.Response The Response object
// @router /api/saml/logout/initiate/:owner/:application [post]
func (c *ApiController) InitiateSamlLogout() {
	host := c.Ctx.Request.Host
	owner := c.Ctx.Input.Param(":owner")
	applicationName := c.Ctx.Input.Param(":application")

	userId := c.GetSessionUsername()
	if userId == "" {
		c.ResponseError(c.T("auth:Please login first"))
		return
	}

	user, err := object.GetUser(userId)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if user == nil {
		c.ResponseError(fmt.Sprintf(c.T("general:The user: %s doesn't exist"), userId))
		return
	}

	application, err := object.GetApplication(fmt.Sprintf("%s/%s", owner, applicationName))
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if application == nil {
		c.ResponseError(fmt.Sprintf(c.T("auth:The application: %s does not exist"), applicationName))
		return
	}

	// Generate SAML logout request
	sessionIndex := c.Ctx.Input.CruSession.SessionID()
	logoutRequest, destination, err := object.GetSamlLogoutRequest(application, user, host, sessionIndex)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	// Clear local session
	c.ClearUserSession()
	c.ClearTokenSession()
	owner, username := util.GetOwnerAndNameFromId(userId)
	_, err = object.DeleteSessionId(util.GetSessionId(owner, username, object.CasdoorApplication), c.Ctx.Input.CruSession.SessionID())
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	util.LogInfo(c.Ctx, "API: [%s] initiated SAML SLO", userId)

	// Return logout request and destination
	c.ResponseOk(map[string]interface{}{
		"logoutRequest": logoutRequest,
		"destination":   destination,
		"method":        "POST",
	})
}
