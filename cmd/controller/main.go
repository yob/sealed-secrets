package main

import (
	"crypto/x509"
	goflag "flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	flag "github.com/spf13/pflag"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	sealedsecrets "github.com/bitnami-labs/sealed-secrets/pkg/client/clientset/versioned"
	ssinformers "github.com/bitnami-labs/sealed-secrets/pkg/client/informers/externalversions"
)

var (
	keyName      = flag.String("key-name", "sealed-secrets-key", "Name of Secret containing public/private key.")
	keySize      = flag.Int("key-size", 4096, "Size of encryption key.")
	validFor     = flag.Duration("key-ttl", 10*365*24*time.Hour, "Duration that certificate is valid for.")
	myCN         = flag.String("my-cn", "", "CN to use in generated certificate.")
	printVersion = flag.Bool("version", false, "Print version information and exit")

	// VERSION set from Makefile
	VERSION = "UNKNOWN"
)

func init() {
	// Standard goflags (glog in particular)
	flag.CommandLine.AddGoFlagSet(goflag.CommandLine)
	if f := flag.CommandLine.Lookup("logtostderr"); f != nil {
		f.DefValue = "true"
		f.Value.Set(f.DefValue)
	}
}

type controller struct {
	clientset kubernetes.Interface
}

func main2() error {
	config, err := rest.InClusterConfig()
	if err != nil {
		return err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	ssclient, err := sealedsecrets.NewForConfig(config)
	if err != nil {
		return err
	}

	ssinformer := ssinformers.NewSharedInformerFactory(ssclient, 0)
	controller := NewController(clientset, ssinformer, *keyName)

	stop := make(chan struct{})
	defer close(stop)

	go controller.Run(stop)

	certs := make([]*x509.Certificate, 0)
	go httpserver(func() ([]*x509.Certificate, error) { return certs, nil }, controller.AttemptUnseal)

	sigterm := make(chan os.Signal, 1)
	signal.Notify(sigterm, syscall.SIGTERM)
	<-sigterm

	return nil
}

func main() {
	flag.Parse()
	goflag.CommandLine.Parse([]string{})

	if *printVersion {
		fmt.Printf("controller version: %s\n", VERSION)
		return
	}

	log.Printf("Starting sealed-secrets controller version: %s\n", VERSION)

	if err := main2(); err != nil {
		panic(err.Error())
	}
}
