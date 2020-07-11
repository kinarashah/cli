package cmd

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	url2 "net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rancher/norman/types/convert"
	managementClient "github.com/rancher/types/client/management/v3"
	"github.com/urfave/cli"
	"golang.org/x/crypto/ssh/terminal"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
)

const kubeConfigCache = "/.cache/token"

var samlProviders = map[string]bool{
	"pingProvider":       true,
	"adfsProvider":       true,
	"keycloakProvider":   true,
	"oktaProvider":       true,
	"shibbolethProvider": true,
}

type LoginInput struct {
	server       string
	userId       string
	clusterId    string
	authProvider string
	caCerts      string
	skipVerify   bool
}


func CredentialCommand() cli.Command {
	return cli.Command{
		Name:        "token",
		Usage:       "Authenticate and generate new kubeconfig token",
		Description: "todo",
		Action:      runCredential,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "server",
				Usage: "Name of rancher server",
			},
			cli.StringFlag{
				Name: "user",
				Usage: "user-id",
			},
			cli.StringFlag{
				Name: "cluster",
				Usage: "cluster-id",
			},
			cli.StringFlag{
				Name:  "auth-provider",
				Usage: "Name of Auth Provider to use for authentication",
			},
			cli.StringFlag{
				Name:  "cacerts",
				Usage: "Location of CaCerts to use",
			},
			cli.BoolFlag{
				Name:  "skip-verify",
				Usage: "Skip verification of the CACerts presented by the Server",
			},
		},
	}
}

func customprompt(field string, show bool) (result string, err error) {

	fmt.Fprintf(os.Stderr, "Please enter %s: ", field)

	if show {
		_, err = fmt.Fscan(os.Stdin, &result)
	} else {
		var data []byte
		data, err = terminal.ReadPassword(int(os.Stdin.Fd()))
		result = string(data)
		fmt.Fprintf(os.Stderr, "\n")
	}
	return result, err

}

func customprint(data interface{}) {
	fmt.Fprintf(os.Stderr, "%v", data)
}

func loadCachedCredential(key string) (*v1beta1.ExecCredential, error) {
	dir, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	cachePath := filepath.Join(dir, kubeConfigCache, fmt.Sprintf("%s.json",key))

	f, err := os.Open(cachePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}

		return nil, err
	}

	defer f.Close()

	var execCredential *v1beta1.ExecCredential
	if err := json.NewDecoder(f).Decode(&execCredential); err != nil {
		return nil, err
	}

	ts := execCredential.Status.ExpirationTimestamp
	customprint(ts)

	if ts != nil && ts.Time.Before(time.Now()) {
		err = os.Remove(cachePath)
		return nil, err
	}

	return execCredential, nil
}

func getAuthProviders(server string) (map[string]string, error) {
	authProviders := fmt.Sprintf("%s/v3-public/authProviders", server)
	req, err := http.NewRequest("GET", authProviders, nil)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	content, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	providers := map[string]string{}
	data := map[string]interface{}{}
	err = json.Unmarshal(content, &data)
	if err != nil {
		return nil, err
	}
	for key, value := range convert.ToMapSlice(data["data"]) {
		provider := convert.ToString(value["type"])
		if provider != "" {
			providers[fmt.Sprintf("%v", key)] = provider
		}
	}
	return providers, err
}

func getAuthProvider(server string) (string, error) {
	authProviders, err := getAuthProviders(server)
	if err != nil || authProviders == nil {
		return "", err
	}
	if len(authProviders) == 0 {
		return "", fmt.Errorf("no auth provider configured")
	}

	if len(authProviders) == 1 {
		return authProviders["0"], nil
	} else {
		try := 0
		providers := []string{}

		for key, val := range authProviders {
			providers = append(providers, fmt.Sprintf("%s - %s", key, val))
		}

		for try < 3 {
			provider, err := customprompt(fmt.Sprintf("pick auth provider \n %v", providers), true)
			if err != nil {
				customprint(err)
				try += 1
				continue
			}
			if _, ok := authProviders[provider]; !ok {
				customprint("pick valid auth provider")
				try += 1
				continue
			}
			provider = authProviders[provider]
			return provider, nil
		}
	}
	return "", fmt.Errorf("invalid auth provider")
}

func getTLSConfig(input *LoginInput) (*tls.Config, error) {
	config := &tls.Config{}
	if input.caCerts != "" {
		cert, err := loadAndVerifyCert(input.caCerts)
		if err != nil {
			return nil, err
		}
		roots := x509.NewCertPool()
		ok := roots.AppendCertsFromPEM([]byte(cert))
		if !ok {
			return nil, err
		}
		config.RootCAs = roots
	}

	if input.skipVerify || input.caCerts == "" {
		config = &tls.Config{
			InsecureSkipVerify: true,
		}
	}

	return config, nil
}

func openBrowser(url string) {
	var err error
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}
	if err != nil {
		log.Fatal(err)
	}

	cmd := exec.Command("open", "-na", "Google Chrome", "--args", "--incognito", url)
	log.Printf(cmd.String())

	if err := cmd.Run(); err != nil {
		log.Printf(fmt.Sprintf("Got error: %s\n", err.Error()))
	}
}

func generateKey() (string, error) {
	characters  := "abcdfghjklmnpqrstvwxz12456789"
	tokenLength := 32
	token := make([]byte, tokenLength)
	for i := range token {
		r, err := rand.Int(rand.Reader, big.NewInt(int64(len(characters))))
		if err != nil {
			return "", err
		}
		token[i] = characters[r.Int64()]
		}

	return string(token), nil
}

func samlAuth(input *LoginInput, tlsConfig *tls.Config) (managementClient.Token, error) {

	customprint("authEnter here")
	token := managementClient.Token{}

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	dialer := websocket.Dialer{
		TLSClientConfig: tlsConfig,
	}

	obj, err := url2.Parse(input.server)

	customprint(obj.Host)

	url := fmt.Sprintf("wss://%s/kubeconfig-token", obj.Host)

	c, _, err := dialer.Dial(url, nil)
	if err != nil {
		return token, err
	}
	defer c.Close()

	key, err := generateKey()
	if err != nil {
		return token, err
	}

	customprint(key)

	send := map[string]string{"wsId": key}
	sendJson, err := json.Marshal(send)
	if err != nil {
		return token, err
	}

	err = c.WriteMessage(websocket.TextMessage, sendJson)
	if err != nil {
		customprint(fmt.Sprintf("write:", err))
		return token, err
	}

	//openBrowser(input.server)
	customprint(fmt.Sprintf("\n Login to Rancher Server at %s/login?socketId=%s \n \n", input.server, key))

	tokenChan := make(chan managementClient.Token)

	go func() {
			data := managementClient.Token{}
			customprint(fmt.Sprintf("waiting for login"))
			_, message, err := c.ReadMessage()
			if err != nil {
				customprint(fmt.Sprintf("error reading message %v", err))
			}

			err = json.Unmarshal(message, &data)
			if err != nil {
				customprint(fmt.Sprintf("error getting token %v", err))
			}

			tokenChan <- data
			return
	}()

	// timeout for user to login and get token
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case t := <-tokenChan:
			token = t
			break

		case <-ticker.C:
			break

		case <-interrupt:
			customprint("received interrupt")
			break
		}
		break
	}

	err = c.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	if err != nil {
		customprint(fmt.Sprintf("write close: %v", err))
		return token, err
	}

	select {
	case <-time.After(2 * time.Second):
		customprint("timeout")
	}

	return token, nil

}

func promptAuth(input *LoginInput, tlsConfig *tls.Config) (managementClient.Token, error) {
	token := managementClient.Token{}
	username, err := customprompt("username", true)
	if err != nil {
		return token, err
	}

	password, err := customprompt("password", false)
	if err != nil {
		return token, err
	}

	responseType := "kubeconfig"
	if input.clusterId != "" {
		responseType = fmt.Sprintf("%s_%s", responseType, input.clusterId)
	}

	body := []byte(fmt.Sprintf(`{"responseType":"%s", "username":"%s", "password":"%s"}`, responseType, username, password))

	url := fmt.Sprintf("%sv3-public/%ss/%s?action=login", input.server, input.authProvider,
		strings.Replace(input.authProvider, "Provider", "", 1))

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return token, err
	}

	req.Header.Set("content-type", "application/json")
	req.Header.Set("accept", "application/json")

	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	client := &http.Client{Transport: tr, Timeout: 300 * time.Second}

	res, err := client.Do(req)
	if err != nil {
		return token, err
	}

	defer res.Body.Close()

	content, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return token, err
	}

	err = json.Unmarshal(content, &token)
	if err != nil {
		customprint(fmt.Sprintf("error getting token %v", err))
		return token, err
	}

	return token, nil
}

func loginAndGenerateCred(input *LoginInput) (*v1beta1.ExecCredential, error) {
	if input.authProvider == "" {
		provider, err := getAuthProvider(input.server)
		if err != nil {
			return nil, err
		}

		input.authProvider = provider
	}

	saml := samlProviders[input.authProvider]

	tlsConfig, err := getTLSConfig(input)
	if err != nil {
		return nil, err
	}

	token := managementClient.Token{}

	if saml {
		customprint("enter here...")
		token, err = samlAuth(input, tlsConfig)
		if err != nil {
			return nil, err
		}
	} else {
		customprint(fmt.Sprintf("Enter credentials for %s \n", input.authProvider))
		token, err = promptAuth(input, tlsConfig)
		if err != nil {
			return nil, err
		}
	}

	cred := &v1beta1.ExecCredential{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ExecCredential",
			APIVersion: v1beta1.SchemeGroupVersion.String(),
		},
		Status: &v1beta1.ExecCredentialStatus{},
	}
	cred.Status.Token = token.Token
	ts, err := time.Parse(time.RFC3339, token.ExpiresAt)
	if err != nil {
		customprint(fmt.Sprintf("%\n error parsing time %s %v", token.ExpiresAt, err))
		return nil, err
	}

	customprint(fmt.Sprintf("\n reached here token: %s", token.Token))

	cred.Status.ExpirationTimestamp = &metav1.Time{Time: ts}

	return cred, nil

}

func cacheCredential(cred *v1beta1.ExecCredential, id string) error {
	if cred.Status.ExpirationTimestamp.IsZero() || cred.Status.Token == "" {
		return nil
	}

	dir, err := os.Getwd()
	if err != nil {
		return err
	}

	cachePathDir := filepath.Join(dir, kubeConfigCache)
	if err := os.MkdirAll(cachePathDir, os.FileMode(0700)); err != nil {
		return err
	}

	path := filepath.Join(cachePathDir, fmt.Sprintf("%s.json", id))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_TRUNC, os.FileMode(0600))
	if err != nil {
		return err
	}

	defer f.Close()

	return json.NewEncoder(f).Encode(cred)
}

func runCredential(ctx *cli.Context) error {
	server := ctx.String("server")
	if server == "" {
		return fmt.Errorf("name of rancher server is required")
	}

	url, err := url2.Parse(server)
	if err != nil {
		return err
	}

	if url.Scheme == "" {
		server = fmt.Sprintf("https://%s/", server)
	}

	userId := ctx.String("user")
	if userId == "" {
		return fmt.Errorf("user-id is required")
	}

	clusterId := ctx.String("cluster")

	customprint(clusterId)

	cachedCred, err := loadCachedCredential(fmt.Sprintf("%s_%s", userId, clusterId))
	if err != nil {
		customprint(fmt.Errorf("LoadToken: %v", err))
	}

	if cachedCred != nil {
		return json.NewEncoder(os.Stdout).Encode(cachedCred)
	}

	input := &LoginInput{
		server:       server,
		userId:       userId,
		clusterId:    clusterId,
		authProvider: ctx.String("auth-provider"),
		caCerts:      ctx.String("cacerts"),
		skipVerify:   ctx.Bool("skip-verify"),
	}

	newCred, err := loginAndGenerateCred(input)
	if err != nil {
		return err
	}

	//customprint(newCred.Status.Token)

	if err := cacheCredential(newCred, fmt.Sprintf("%s_%s", userId, clusterId)); err != nil {
		customprint(fmt.Errorf("CacheToken: %v", err))
	}

	customprint(fmt.Sprintf("\n"))

	return json.NewEncoder(os.Stdout).Encode(newCred)
}
