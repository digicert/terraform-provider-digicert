package main

import (
	"context"
	"flag"
	"log"

	digicert "github.com/digicert/digicert-terraform-provider/internal/digicert"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
)

var (
	version string = "dev"
)

func main() {
	var debug bool

	flag.BoolVar(&debug, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()

	opts := providerserver.ServeOpts{
		Address: "registry.terraform.io/digicert/digicert",
		Debug:   debug,
	}

	err := providerserver.Serve(context.Background(), digicert.New(version), opts)

	if err != nil {
		log.Fatal(err.Error())
	}
}
