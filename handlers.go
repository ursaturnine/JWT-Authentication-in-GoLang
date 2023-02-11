package main

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
)

// jwtKey which we'll use in our jwt token
var jwtKey = []byte("secret_key")

// dummy data
var users = map[string]string{
	"user1": "password1",
	"user2": "password2",
}

// user credentrials struct
// add JSON info bc we'll take data in as JSON format
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// claims used to create a payload for the jwt
// payload will have user and expiry
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

// r is the request object
func Login(w http.ResponseWriter, r *http.Request) {
	var credentials Credentials
	// store the data in cookies and pass the request back
	// 1. take JSON from the JSON Decoder
	// -take body of request to decode and decode to reference of 'credentials'
	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// match the data we've decoded to the data in our dummy data
	// the user we get from the credentials password gets an expectedPassword of 'ok'
	expectedPassword, ok := users[credentials.Username]
	// if password is incorrect
	if !ok || expectedPassword != credentials.Password {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	// if authorized, assign a claim
	// expiration time of token is 5 minutes
	expirationTime := time.Now().Add(time.Minute * 5)

	claims := &Claims{
		Username: credentials.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	// create token to use with claims
	token := jwt.NewWithClaims(jwt.SigninMethodHS256, claims)
	// get the token string from above data
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// no error? set cookies
	// session cookie will be saved to browser or wherever
	http.SetCookie(w,
		&http.Cookie{
			Name:    "token",
			Value:   tokenString,
			Expires: expirationTime,
		})

}
func Home(w http.ResponseWriter, r *http.Request)    {}
func Refresh(w http.ResponseWriter, r *http.Request) {}
