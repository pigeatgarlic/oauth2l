// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package internal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"sync"
)

// Account represents the credentials used to authorize
// the requests to access protected resources on the OAuth 2.0
// provider's backend.
//
// This type is a mirror of oauth2.Account and exists to break
// an otherwise-circular dependency. Other internal packages
// should convert this Account into an oauth2.Account before use.
type Account struct {
	Username string			`json:"username"`
	Password string			`json:"password"`

	// Raw optionally contains extra metadata from the server
	// when updating a token.
	Raw interface{}
}

// RegisterBrokenAuthHeaderProvider previously did something. It is now a no-op.
//
// Deprecated: this function no longer does anything. Caller code that
// wants to avoid potential extra HTTP requests made during
// auto-probing of the provider's auth style should set
// Endpoint.AuthStyle.
func RegisterBrokenAuthHeaderProvider(tokenURL string) {}

// AuthStyle is a copy of the golang.org/x/oauth2 package's AuthStyle type.
type AuthStyle int

const (
	AuthStyleUnknown  AuthStyle = 0
	AuthStyleInParams AuthStyle = 1
	AuthStyleInHeader AuthStyle = 2
)

// authStyleCache is the set of tokenURLs we've successfully used via
// RetrieveToken and which style auth we ended up using.
// It's called a cache, but it doesn't (yet?) shrink. It's expected that
// the set of OAuth2 servers a program contacts over time is fixed and
// small.
var authStyleCache struct {
	sync.Mutex
	m map[string]AuthStyle // keyed by tokenURL
}

// ResetAuthCache resets the global authentication style cache used
// for AuthStyleUnknown token requests.
func ResetAuthCache() {
	authStyleCache.Lock()
	defer authStyleCache.Unlock()
	authStyleCache.m = nil
}

func RetrieveToken(exchange_api string,authdata interface{} , anon_token string, v url.Values) (*Account, error) {
	data,err := json.Marshal(authdata)
	if err != nil {
		return nil,err
	}

	req, _ := http.NewRequest("POST", exchange_api, bytes.NewReader(data))
	req.Header.Set("Oauth2-Token", v.Encode())
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s",anon_token))

	r, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func ()  {
		r.Body.Close()
	}()

	body, err := ioutil.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, err
	}


	token := &Account{ }
	err = json.Unmarshal(body,token)
	if err != nil {
		return nil, err
	}

	return token, nil
}


