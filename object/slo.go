package object

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"time"

	"github.com/casdoor/casdoor/util"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func getIssuerForHost(host string) string {
	_, originBackend := getOriginFromHost(host)
	return originBackend
}

func GenerateBackchannelLogoutToken(application *Application, session *SsoSession, host string, subject string) (string, error) {
	if session == nil || session.Sid == "" {
		return "", fmt.Errorf("slo: session sid is empty")
	}

	issuer := getIssuerForHost(host)
	claims := jwt.MapClaims{
		"iss":    issuer,
		"aud":    session.ClientId,
		"iat":    time.Now().Unix(),
		"jti":    util.GenerateId(),
		"sid":    session.Sid,
		"events": map[string]map[string]any{"http://schemas.openid.net/event/backchannel-logout": {}},
	}

	if subject != "" {
		claims["sub"] = subject
	}

	return signJwtWithApplication(application, claims)
}

func BuildFrontchannelLogoutURL(application *Application, session *SsoSession, host string) (string, error) {
	if session == nil || session.Sid == "" {
		return "", fmt.Errorf("slo: session sid is empty")
	}
	if session.FrontchannelLogoutUri == "" {
		return "", nil
	}

	issuer := getIssuerForHost(host)
	logoutURL, err := url.Parse(session.FrontchannelLogoutUri)
	if err != nil {
		return "", err
	}

	query := logoutURL.Query()
	query.Set("sid", session.Sid)
	query.Set("iss", issuer)
	logoutURL.RawQuery = query.Encode()

	return logoutURL.String(), nil
}

func GenerateSamlLogoutRequest(application *Application, session *SsoSession, host string) (string, string, error) {
	if session == nil || session.SessionIndex == "" || session.NameId == "" {
		return "", "", fmt.Errorf("slo: saml session information incomplete")
	}
	if application.SamlSingleLogoutServiceUrl == "" {
		return "", "", fmt.Errorf("slo: single logout service url is empty")
	}

	requestID := fmt.Sprintf("_%s", uuid.NewString())
	issueInstant := time.Now().UTC().Format(time.RFC3339)
	issuer := host
	logoutRequest := fmt.Sprintf(`<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" Version="2.0" IssueInstant="%s" Destination="%s"><saml:Issuer>%s</saml:Issuer><saml:NameID>%s</saml:NameID><samlp:SessionIndex>%s</samlp:SessionIndex></samlp:LogoutRequest>`,
		requestID, issueInstant, application.SamlSingleLogoutServiceUrl, issuer, session.NameId, session.SessionIndex)

	encoded := base64.StdEncoding.EncodeToString([]byte(logoutRequest))
	return application.SamlSingleLogoutServiceUrl, encoded, nil
}

func GenerateCasLogoutRequest(session *SsoSession) (string, string, error) {
	if session == nil || session.ServiceUrl == "" || session.SessionIndex == "" {
		return "", "", fmt.Errorf("slo: cas session information incomplete")
	}

	nameId := session.NameId
	if nameId == "" {
		nameId = session.SessionIndex
	}
	logoutRequest := fmt.Sprintf(`<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="%s" Version="2.0" IssueInstant="%s"><saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml:NameID><samlp:SessionIndex>%s</samlp:SessionIndex></samlp:LogoutRequest>`,
		"LR-"+uuid.NewString(), time.Now().UTC().Format(time.RFC3339), nameId, session.SessionIndex)

	return session.ServiceUrl, logoutRequest, nil
}
