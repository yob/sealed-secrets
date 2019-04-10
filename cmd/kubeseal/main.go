package main

import (
	goflag "flag"
	"fmt"
	"io"
	"io/ioutil"
	"k8s.io/apimachinery/pkg/util/net"
	"net/http"
	"os"
	"strings"

	flag "github.com/spf13/pflag"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	runtimeserializer "k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes/scheme"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/clientcmd"

	ssv1alpha1 "github.com/bitnami-labs/sealed-secrets/pkg/apis/sealed-secrets/v1alpha1"

	// Register Auth providers
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
)

var (
	// TODO: Verify k8s server signature against cert in kube client config.
	certFile       = flag.String("cert", "", "Certificate / public key to use for encryption. Overrides --controller-*")
	controllerNs   = flag.String("controller-namespace", metav1.NamespaceSystem, "Namespace of sealed-secrets controller.")
	controllerName = flag.String("controller-name", "sealed-secrets-controller", "Name of sealed-secrets controller.")
	kmsKeyName     = flag.String("kms-key", "", "KMS key name to encrypt with")
	outputFormat   = flag.String("format", "json", "Output format for sealed secret. Either json or yaml")
	dumpCert       = flag.Bool("fetch-cert", false, "Write certificate to stdout.  Useful for later use with --cert")
	printVersion   = flag.Bool("version", false, "Print version information and exit")
	validateSecret = flag.Bool("validate", false, "Validate that the sealed secret can be decrypted")

	// VERSION set from Makefile
	VERSION = "UNKNOWN"

	clientConfig clientcmd.ClientConfig
)

func init() {
	// The "usual" clientcmd/kubectl flags
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	loadingRules.DefaultClientConfig = &clientcmd.DefaultClientConfig
	overrides := clientcmd.ConfigOverrides{}
	kflags := clientcmd.RecommendedConfigOverrideFlags("")
	flag.StringVar(&loadingRules.ExplicitPath, "kubeconfig", "", "Path to a kube config. Only required if out-of-cluster")
	clientcmd.BindOverrideFlags(&overrides, flag.CommandLine, kflags)
	clientConfig = clientcmd.NewInteractiveDeferredLoadingClientConfig(loadingRules, &overrides, os.Stdin)

	// Standard goflags (glog in particular)
	flag.CommandLine.AddGoFlagSet(goflag.CommandLine)
}

func readSecret(codec runtime.Decoder, r io.Reader) (*v1.Secret, error) {
	data, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var ret v1.Secret
	if err = runtime.DecodeInto(codec, data, &ret); err != nil {
		return nil, err
	}

	return &ret, nil
}

func prettyEncoder(codecs runtimeserializer.CodecFactory, mediaType string, gv runtime.GroupVersioner) (runtime.Encoder, error) {
	info, ok := runtime.SerializerInfoForMediaType(codecs.SupportedMediaTypes(), mediaType)
	if !ok {
		return nil, fmt.Errorf("binary can't serialize %s", mediaType)
	}

	prettyEncoder := info.PrettySerializer
	if prettyEncoder == nil {
		prettyEncoder = info.Serializer
	}

	enc := codecs.EncoderForVersion(prettyEncoder, gv)
	return enc, nil
}

func seal(in io.Reader, out io.Writer, codecs runtimeserializer.CodecFactory, keyName string) error {
	secret, err := readSecret(codecs.UniversalDecoder(), in)
	if err != nil {
		return err
	}

	if len(secret.Data) == 0 {
		// No data. This is _theoretically_ just fine, but
		// almost certainly indicates a misuse of the tools.
		// If you _really_ want to encrypt an empty secret,
		// then a PR to skip this check with some sort of
		// --force flag would be welcomed.
		return fmt.Errorf("Secret.data is empty in input Secret, assuming this is an error and aborting")
	}

	if secret.GetName() == "" {
		return fmt.Errorf("Missing metadata.name in input Secret")
	}

	if secret.GetNamespace() == "" {
		ns, _, err := clientConfig.Namespace()
		if err != nil {
			return err
		}
		secret.SetNamespace(ns)
	}

	// Strip read-only server-side ObjectMeta (if present)
	secret.SetSelfLink("")
	secret.SetUID("")
	secret.SetResourceVersion("")
	secret.Generation = 0
	secret.SetCreationTimestamp(metav1.Time{})
	secret.SetDeletionTimestamp(nil)
	secret.DeletionGracePeriodSeconds = nil

	ssecret, err := ssv1alpha1.NewSealedSecret(codecs, keyName, secret)
	if err != nil {
		return err
	}

	var contentType string
	switch strings.ToLower(*outputFormat) {
	case "json", "":
		contentType = runtime.ContentTypeJSON
	case "yaml":
		contentType = "application/yaml"
	default:
		return fmt.Errorf("unsupported output format: %s", *outputFormat)

	}
	prettyEnc, err := prettyEncoder(codecs, contentType, ssv1alpha1.SchemeGroupVersion)
	if err != nil {
		return err
	}

	buf, err := runtime.Encode(prettyEnc, ssecret)
	if err != nil {
		return err
	}

	out.Write(buf)
	fmt.Fprint(out, "\n")

	return nil
}

func validateSealedSecret(in io.Reader, namespace, name string) error {
	conf, err := clientConfig.ClientConfig()
	if err != nil {
		return err
	}
	restClient, err := corev1.NewForConfig(conf)
	if err != nil {
		return err
	}

	content, err := ioutil.ReadAll(in)
	if err != nil {
		return err
	}

	req := restClient.RESTClient().Post().
		Namespace(namespace).
		Resource("services").
		SubResource("proxy").
		Name(net.JoinSchemeNamePort("http", name, "")).
		Suffix("/v1/verify")

	req.Body(content)
	res := req.Do()
	if err := res.Error(); err != nil {
		if status, ok := err.(*k8serrors.StatusError); ok && status.Status().Code == http.StatusConflict {
			return fmt.Errorf("Unable to decrypt sealed secret")
		}
		return fmt.Errorf("Error occurred while validating sealed secret")
	}

	return nil
}

func main() {
	flag.Parse()
	goflag.CommandLine.Parse([]string{})

	if *printVersion {
		fmt.Printf("kubeseal version: %s\n", VERSION)
		return
	}

	if *validateSecret {
		err := validateSealedSecret(os.Stdin, *controllerNs, *controllerName)
		if err != nil {
			panic(err.Error())
		}
		return
	}

	if err := seal(os.Stdin, os.Stdout, scheme.Codecs, *kmsKeyName); err != nil {
		panic(err.Error())
	}
}
