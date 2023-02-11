package main

import (
	"log"
	"net/http"
)

func main() {
	// Handler functions
	http.HandleFunc("/login", Login)
	http.HandleFunc("/home", Home)
	// http.HandleFunc("/refresh", Refresh)

	// print errors if any
	// listen on port 8080 and no routing framework
	log.Fatal(http.ListenAndServe(":8080", nil))
}
