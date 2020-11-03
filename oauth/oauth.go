package oauth

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-resty/resty/v2"
	"github.com/yesseneon/bookstore_utils/errors"
)

const (
	headerXPublic   = "X-Public"
	headerXClientID = "X-ClientID"
	headerXCallerID = "X-CallerID"
)

type oauthClient struct {
}

type oauthInterface struct {
}

type accessToken struct {
	ID       int `json:"id"`
	UserID   int `json:"user_id"`
	ClientID int `json:"client_id"`
}

func IsPublic(r *http.Request) bool {
	if r == nil {
		return true
	}

	return r.Header.Get(headerXPublic) == "true"
}

func GetClientID(r *http.Request) int {
	if r == nil {
		return 0
	}

	clientID, err := strconv.Atoi(r.Header.Get(headerXClientID))
	if err != nil {
		return 0
	}

	return clientID
}

func GetCallerID(r *http.Request) int {
	if r == nil {
		return 0
	}

	callerID, err := strconv.Atoi(r.Header.Get(headerXCallerID))
	if err != nil {
		return 0
	}

	return callerID
}

func AuthenticateUser(r *http.Request) *errors.RESTError {
	if r == nil {
		return nil
	}

	cleanRequest(r)

	accessTokenID := strings.TrimSpace(r.URL.Query().Get("access_token"))
	if accessTokenID == "" {
		return nil
	}

	at, restErr := getAccessToken(accessTokenID)
	if restErr != nil {
		if restErr.Status == http.StatusNotFound {
			return nil
		}

		return restErr
	}

	r.Header.Add(headerXClientID, fmt.Sprintf("%v", at.ClientID))
	r.Header.Add(headerXCallerID, fmt.Sprintf("%v", at.UserID))

	return nil
}

func cleanRequest(r *http.Request) {
	if r == nil {
		return
	}

	r.Header.Del(headerXClientID)
	r.Header.Del(headerXCallerID)
}

func getAccessToken(accessTokenID string) (*accessToken, *errors.RESTError) {
	// var restErr *errors.RESTError
	resp, err := resty.New().R().
		EnableTrace().
		Get(fmt.Sprintf("http://localhost:8080/oauth/access_token/%s", accessTokenID))

	log.Println(resp)
	log.Println(err)
	if err != nil {
		return nil, errors.InternalServerError()
	}

	var at *accessToken

	return at, nil
}
