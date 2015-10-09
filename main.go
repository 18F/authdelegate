package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
)

func usage() {
	fmt.Printf("Usage: %s config.json\n", os.Args[0])
}

func printErrorAndExit(operation, configPath string, err error) {
	fmt.Printf("Error %s %s: %s\n", operation, configPath, err.Error())
	os.Exit(1)
}

func main() {
	if len(os.Args) != 2 {
		usage()
		os.Exit(1)
	}

	configPath := os.Args[1]
	var configBytes []byte
	var err error

	if configBytes, err = ioutil.ReadFile(configPath); err != nil {
		printErrorAndExit("reading", configPath, err)
	}

	var opts *AuthDelegateOptions
	if opts, err = NewAuthDelegateOptionsFromJSON(configBytes); err != nil {
		printErrorAndExit("parsing", configPath, err)
	}

	address := ":" + strconv.Itoa(opts.Port)
	handler := NewAuthDelegate(opts)
	server := &http.Server{Addr: address, Handler: handler}
	fmt.Printf("port %d: awaiting auth delegation requests\n", opts.Port)

	if opts.SslCert != "" {
		err = server.ListenAndServeTLS(opts.SslCert, opts.SslKey)
	} else {
		err = server.ListenAndServe()
	}
	log.Fatal(err)
}
