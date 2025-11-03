package object

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/casdoor/casdoor/util"
	"github.com/golang-jwt/jwt/v5"
)

func resolveSigningKey(application *Application, cert *Cert) (interface{}, jwt.SigningMethod, error) {
	signingMethod := application.TokenSigningMethod
	if signingMethod == "" {
		signingMethod = "RS256"
	}

	var (
		key interface{}
		err error
	)

	switch {
	case strings.HasPrefix(signingMethod, "RS"):
		key, err = jwt.ParseRSAPrivateKeyFromPEM([]byte(cert.PrivateKey))
	case strings.HasPrefix(signingMethod, "ES"):
		key, err = jwt.ParseECPrivateKeyFromPEM([]byte(cert.PrivateKey))
	case strings.HasPrefix(signingMethod, "Ed"):
		key, err = jwt.ParseEdPrivateKeyFromPEM([]byte(cert.PrivateKey))
	default:
		key, err = jwt.ParseRSAPrivateKeyFromPEM([]byte(cert.PrivateKey))
		if err == nil {
			signingMethod = "RS256"
		}
	}

	if err != nil {
		return nil, nil, err
	}

	method := jwt.GetSigningMethod(signingMethod)
	if method == nil {
		return nil, nil, fmt.Errorf("unsupported signing method: %s", signingMethod)
	}

	return key, method, nil
}

func GenerateBackchannelLogoutToken(application *Application, session *SloSession, host string) (string, error) {
	if session.Sid == "" {
		return "", fmt.Errorf("sid is empty for session %s", session.GetId())
	}

	cert, err := getCertByApplication(application)
	if err != nil {
		return "", err
	}
	if cert == nil {
		return "", fmt.Errorf("cert %s not found", application.Cert)
	}

	key, signingMethod, err := resolveSigningKey(application, cert)
	if err != nil {
		return "", err
	}

	_, originBackend := getOriginFromHost(host)
	claims := jwt.MapClaims{
		"iss": originBackend,
		"aud": application.ClientId,
		"iat": time.Now().Unix(),
		"jti": util.GenerateId(),
		"sid": session.Sid,
		"events": map[string]map[string]interface{}{
			"http://schemas.openid.net/event/backchannel-logout": {},
		},
	}

	logoutToken := jwt.NewWithClaims(signingMethod, claims)
	logoutToken.Header["kid"] = cert.Name
	signed, err := logoutToken.SignedString(key)
	if err != nil {
		return "", err
	}

	return signed, nil
}

func SendBackchannelLogout(application *Application, session *SloSession, host string) error {
	if session.BackChannelLogoutUri == "" {
		return nil
	}

	logoutToken, err := GenerateBackchannelLogoutToken(application, session, host)
	if err != nil {
		return err
	}

	values := url.Values{}
	values.Set("logout_token", logoutToken)
	request, err := http.NewRequest(http.MethodPost, session.BackChannelLogoutUri, bytes.NewBufferString(values.Encode()))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("backchannel logout request failed with status %d", response.StatusCode)
	}

	return nil
}

func BuildFrontchannelLogoutURL(application *Application, session *SloSession, host string) (string, error) {
	if session.FrontChannelLogoutUri == "" {
		return "", nil
	}

	logoutURL, err := url.Parse(session.FrontChannelLogoutUri)
	if err != nil {
		return "", err
	}

	query := logoutURL.Query()
	_, originBackend := getOriginFromHost(host)
	query.Set("iss", originBackend)
	if application.FrontChannelLogoutSessionRequired && session.Sid != "" {
		query.Set("sid", session.Sid)
	}
	logoutURL.RawQuery = query.Encode()

	return logoutURL.String(), nil
}
