package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
)

var (
	version = "dev"
)

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "set to true to run the provider with support for debuggers")
	flag.Parse()

	opts := providerserver.ServeOpts{
		Address: "registry.terraform.io/Mourad-Soltani/aca",
		Debug:   debug,
	}

	err := providerserver.Serve(context.Background(), NewProvider, opts)
	if err != nil {
		log.Fatal(err.Error())
	}
}
