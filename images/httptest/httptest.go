package main

import (
	"io"
	"net/http"
	"os"
)

var hostname string

func RootRoute(w http.ResponseWriter, req *http.Request) {
	io.WriteString(w, hostname)
}

func main() {
	hostname, _ = os.Hostname()

	http.HandleFunc("/", RootRoute)
	http.ListenAndServe(":80", nil)
}
