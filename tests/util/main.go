package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/codegangsta/cli"
)

// TestServer is invoked for the `test-server` command
func TestServer(c *cli.Context) error {
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Not technically a response header, but we'll use it
		w.Header().Set("Host", hostname)
		w.WriteHeader(http.StatusOK)
		msSleep := c.Int("request-time")
		time.Sleep(time.Duration(msSleep) * time.Millisecond)
		fmt.Fprintf(w, "OK")
	})
	http.HandleFunc("/fanout", func(w http.ResponseWriter, r *http.Request) {
		// POST to /fanout with a new-line delimited list of URLs to request
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Host", hostname)
		w.WriteHeader(http.StatusOK)
		// Would it make sense to parallelize?
		for _, target := range strings.Split(string(body), "\n") {
			log.Debug("Req: %s -> %s", hostname, target)
			// TODO - mTLS support?
			resp, err := http.Get(target) // TODO Timeouts?
			if err != nil {
				fmt.Fprintf(w, "%s:ERROR:%s\n", target, err)
			} else {
				defer resp.Body.Close()
				b, _ := ioutil.ReadAll(resp.Body)
				fmt.Fprintf(w, "%s:%d:%s\n", target, resp.StatusCode, strings.TrimSpace(string(b)))
			}
		}
	})
	server := &http.Server{
		Addr: c.String("listen-address"),
	}

	if c.Bool("tls") {
		log.Info("Configuring TLS")

		if c.Bool("client-auth") {
			caCert, err := ioutil.ReadFile(c.String("ca"))
			if err != nil {
				return err
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			server.TLSConfig = &tls.Config{
				// ListenAndServeTLS will wire up the cert/key pairs automatically
				ClientAuth: tls.RequireAndVerifyClientCert,
				ClientCAs:  caCertPool,
			}
		}

		log.Infof("Listening to HTTPS on %s", c.String("listen-address"))
		return server.ListenAndServeTLS(c.String("cert"), c.String("key"))
	}

	log.Infof("Listening to HTTP on %s", c.String("listen-address"))
	return server.ListenAndServe()

}

func TestTLSServer(c *cli.Context) error {
	if c.String("cert") == "" || c.String("key") == "" {
		log.Fatal("Unable to start ucp-proxy without TLS configuration")
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "OK")
	})
	server := &http.Server{
		Addr: c.String("listen-address"),
	}
	log.Infof("Listening on %s", c.String("listen-address"))
	log.Fatal(server.ListenAndServeTLS(c.String("cert"), c.String("key")))
	return nil
}

// The `test-server` command returns a simple 200 OK at the / endpoint, meant to debug port connectivity
var cmdTestServer = cli.Command{
	Name:  "test-server",
	Usage: "Returns 200 OK at /",
	Description: `
    `,
	Action: TestServer,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "listen-address, l",
			Usage: "Listen Address",
			Value: ":80",
		},
		cli.StringFlag{
			Name:   "ca",
			Usage:  "Path to CA certificate",
			EnvVar: "SSL_CA",
			Value:  "/certs/ca.pem",
		},
		cli.StringFlag{
			Name:   "cert",
			Usage:  "Path to server certificate",
			EnvVar: "SSL_CERT",
			Value:  "/certs/cert.pem",
		},
		cli.StringFlag{
			Name:   "key",
			Usage:  "Path to certificate key",
			EnvVar: "SSL_KEY",
			Value:  "/certs/key.pem",
		},
		cli.BoolFlag{
			Name:  "tls",
			Usage: "Use TLS",
		},
		cli.BoolFlag{
			Name:  "client-auth",
			Usage: "Require client cert authentication for TLS",
		},
		cli.IntFlag{
			Name:  "request-time, ms",
			Usage: "Time to take in milliseconds before responding with OK",
			Value: 0,
		},
	},
}

var cmdTestTLSServer = cli.Command{
	Name:  "test-tls-server",
	Usage: "Returns 200 OK at /",
	Description: `
    `,
	Action: TestTLSServer,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "listen-address, l",
			Usage: "Listen Address",
			Value: ":2376",
		},
		cli.StringFlag{
			Name:   "cert",
			Usage:  "Path to server certificate",
			EnvVar: "SSL_CERT",
		},
		cli.StringFlag{
			Name:   "key",
			Usage:  "Path to certificate key",
			EnvVar: "SSL_KEY",
		},
	},
}

// Driver function
func main() {
	app := cli.NewApp()
	app.Name = "E2E Utility"
	app.Commands = []cli.Command{
		cmdTestServer,
		cmdTestTLSServer,
	}
	log.SetFormatter(&log.JSONFormatter{})

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
}
