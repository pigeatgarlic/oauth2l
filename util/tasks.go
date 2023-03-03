//
// Copyright 2018 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package util

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/pigeatgarlic/oauth2l/tools/oauth2"
)

const (
	// Base URL to fetch the token info
	googleTokenInfoURLPrefix = "https://www.googleapis.com/oauth2/v3/tokeninfo/?access_token="
)

// Supported output formats
const (
	formatJson         = "json"
	formatJsonCompact  = "json_compact"
	formatPretty       = "pretty"
	formatHeader       = "header"
	formatBare         = "bare"
	formatRefreshToken = "refresh_token"
)

// Credentials file types.
// If type is not one of the below, it means the file is a
// Google Client ID JSON.
const (
	serviceAccountKey  = "service_account"
	userCredentialsKey = "authorized_user"
	externalAccountKey = "external_account"
)

// An extensible structure that holds the settings
// used by different oauth2l tasks.
// These settings are used by oauth2l only
// and are not part of GUAC settings.
type TaskSettings struct {
	// AuthType determines which auth tool to use (sso vs sgauth)
	AuthType string
	// Output format for Fetch task
	Format string
	// CurlCli override for Curl task
	CurlCli string
	// Url endpoint for Curl task
	Url string
	// Extra args for Curl task
	ExtraArgs []string
	// SsoCli override for Sso task
	SsoCli string
	// Refresh expired access token in cache
	Refresh bool

	Authdata interface{}
}

// Fetches and prints the token in plain text with the given settings
// using Google Authenticator.
func Fetch(settings *Settings, taskSettings *TaskSettings) (*oauth2.Account,error) {
	return fetchToken(settings, taskSettings)
}

// Fetches and prints the token in header format with the given settings
// using Google Authenticator.
func Header(settings *Settings, taskSettings *TaskSettings) {
	taskSettings.Format = formatHeader
	Fetch(settings, taskSettings)
}

// Fetches token with the given settings using Google Authenticator
// and use the token as header to make curl request.

// Fetches the information of the given token.
func Info(token string) int {
	info, err := getTokenInfo(token)
	if err != nil {
		fmt.Print(err)
	} else {
		fmt.Println(info)
	}
	return 0
}

// Tests the given token. Returns 0 for valid tokens.
// Otherwise returns 1.
func Test(token string) int {
	_, err := getTokenInfo(token)
	if err != nil {
		fmt.Println(1)
		return 1
	} else {
		fmt.Println(0)
		return 0
	}
}

// Resets the cache.
func Reset() {
	err := ClearCache()
	if err != nil {
		fmt.Print(err)
	}
}

// Returns the given token in standard header format.
func BuildHeader(tokenType string, token string) string {
	return fmt.Sprintf("Authorization: %s %s", tokenType, token)
}

func getTokenInfo(token string) (string, error) {
	c := http.DefaultClient
	resp, err := c.Get(googleTokenInfoURLPrefix + token)
	if err != nil {
		return "", err
	}
	data, err := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", errors.New(string(data))
	}
	return string(data), err
}

// fetchToken attempts to fetch and cache an access token.
//
// If SSO is specified, obtain token via SSOFetch instead of FetchToken.
//
// If cached token is expired and refresh is requested,
// attempt to obtain new token via RefreshToken instead
// of default OAuth flow.
//
// If STS is requested, we will perform an STS exchange
// after the original access token has been fetched.
func fetchToken(settings *Settings, taskSettings *TaskSettings) (*oauth2.Account,error) {
	fetchSettings := settings
	fetchSettings.Authdata = taskSettings.Authdata
	token, err := FetchToken(context.Background(), fetchSettings)
	if err != nil {
		return nil,err
	}
	return token,nil
}

