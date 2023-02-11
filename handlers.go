package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
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
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
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

// takes in cookie
// check errors:“
// if no cookie error
// bad request error
// create reference to claims object
// pass JWTKey and return token
// if err is not nil and err is type signature invalid
// -unauthorized request || badrequest
// if token is not valid -unauthorized request
// if data valid, pass data back to client with success message
func Home(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	tokenStr := cookie.Value
	// pass token back using jwtKey
	claims := &Claims{}

	// returns claims object using the tokenString
	tkn, err := jwt.ParseWithClaims(tokenStr, claims,
		func(t *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// if token matches, success message and pass claims back
	w.Write([]byte(fmt.Sprintf("Hello, %s", claims.Username)))

}
func Refresh(w http.ResponseWriter, r *http.Request) {}
