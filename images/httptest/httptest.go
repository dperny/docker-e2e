package main

import (
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

var hostname string

func ProxyRoute(w http.ResponseWriter, req *http.Request) {
	endpoint := req.URL.Path[len("/proxy/"):]
	tr := &http.Transport{}
	client := &http.Client{Transport: tr, Timeout: time.Duration(5 * time.Second)}
	// TODO(dperny) handle custom port, possibly through querystring
	resp, err := client.Get("http://" + endpoint)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(body)
}

func RootRoute(w http.ResponseWriter, req *http.Request) {
	io.WriteString(w, hostname)
}

func main() {
	hostname, _ = os.Hostname()

	http.HandleFunc("/", RootRoute)
	http.HandleFunc("/proxy/", ProxyRoute)
	http.ListenAndServe(":80", nil)
}
