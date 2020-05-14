package cmd

import (
	//"github.com/rancher/types/apis/management.cattle.io/v3public"

	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/rancher/norman/types/convert"
	managementClient "github.com/rancher/types/client/management/v3"
	"io/ioutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	//"strings"

	"github.com/urfave/cli"
	"golang.org/x/crypto/ssh/terminal"
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

func CredentialCommand() cli.Command {
	return cli.Command{
		Name:        "token",
		Usage:       "Authenticate and generate new kubeconfig token",
		Description: "todo",
		Action:      runCredential,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "server",
				Usage: "rancher server",
			},
			cli.StringFlag{
				Name: "user-id",
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

func print(data interface{}) {

	fmt.Fprintf(os.Stderr, "%v", data)
}

func loadCachedCredential(key string) (*v1beta1.ExecCredential, error) {
	dir, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	cachePath := filepath.Join(dir, fmt.Sprintf("%s-%s.json", kubeConfigCache, key))

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
	if ts.Time.Before(time.Now()) {
		err = os.Remove(cachePath)
		return nil, err
	}

	return execCredential, nil
}

func getAuthProviders(server string) (map[string]string, error) {
	authProviders := fmt.Sprintf("%s/v3-public/authProviders", server)
	print(authProviders)

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

	//print("got body")

	content, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	//print(string(content))

	providers := map[string]string{}

	data := map[string]interface{}{}
	err = json.Unmarshal(content, &data)
	if err != nil {
		return nil, err
	}

	//data, _ := convert.EncodeToMap(content)

	//print(data)

	for key, value := range convert.ToMapSlice(data["data"]) {

		//print(fmt.Sprintf("key %v \n", key))
		//
		//print(fmt.Sprintf("value %#v \n", value))

		provider := convert.ToString(value["type"])
		if provider != "" {
			providers[fmt.Sprintf("%v", key)] = provider
		}
	}

	return providers, err
}

func loginAndGenerateCred(server, id string) (*v1beta1.ExecCredential, error) {
	authProviders, err := getAuthProviders(server)
	if err != nil || authProviders == nil {
		return nil, err
	}
	if len(authProviders) == 0 {
		return nil, fmt.Errorf("no auth provider configured")
	}
	key := ""

	if len(authProviders) == 1 {
		key = authProviders["0"]
	} else {
		try := 0
		for try < 3 {
			provider, err := customprompt(fmt.Sprintf("pick auth provider \n %v", authProviders), true)
			if err != nil {
				print(err)
				try += 1
				continue
			}
			if _, ok := authProviders[provider]; !ok {
				print("pick valid auth provider")
				try += 1
				continue
			}
			key = authProviders[provider]
			break
		}
	}

	print(fmt.Sprintf("Enter credentials for %s", key))

	var body []byte

	saml := samlProviders[key]

	if !saml {
		username, err := customprompt("username", true)
		if err != nil {
			return nil, err
		}

		password, err := customprompt("password", false)
		if err != nil {
			return nil, err
		}

		body = []byte(fmt.Sprintf(`{"responseType":"kubeconfig", "username":"%s", "password":"%s"}`, username, password))
		fmt.Print(string(body))

	} else {
		body = []byte(fmt.Sprintf(`{"finalRedirectUrl":"%s"}`, server))
		fmt.Print(string(body))
	}

	url := fmt.Sprintf("%s/v3-public/%ss/%s?action=login", server, key, strings.Replace(key, "Provider", "", 1))

	print(url)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
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

	//print("got body")

	content, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if !saml {
		token := managementClient.Token{}
		err = json.Unmarshal(content, &token)
		if err != nil {
			return nil, err
		}

		fmt.Print(token.Token)
	} else {
		data := map[string]string{}

		err = json.Unmarshal(content, &data)
		if err != nil {
			return nil, err
		}

		idpURL := convert.ToString(data["idpRedirectUrl"])

		//print(fmt.Sprintf("%v\n", data))

		//for key, value := range data {
		//
		//	print(fmt.Sprintf("%s \n", key))
		//
		//	print(fmt.Sprintf("%s \n", value))
		//}

		//params, err := uu.ParseQuery(idpURL)
		//if err != nil {
		//	log.Fatal(err)
		//	return nil, nil
		//}
		//
		//fmt.Println("Query Params: ")
		//for key, value := range params {
		//	fmt.Printf("  %v = %v\n", key, value)
		//}


		print(fmt.Sprintf("\n opening %s \n", idpURL))
		cmd := exec.Command("open", "-na", "Google Chrome","--args", "--incognito",idpURL)
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		print(cmd.String())


		if err := cmd.Run(); err != nil {
			print(fmt.Sprintf("Got error: %s\n", err.Error()))
		}

		//tr = &http.Transport{
		//
		//	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		//}

		//acsURL := fmt.Sprintf("%s/v1-saml/adfs/saml/acs", server)


		//go func(acsURL string) {
		//	i := 0
		//	for i == 0{
		//		print(fmt.Sprintf("\n open connection to %s \n", acsURL))
		//
		//		req, err := http.NewRequest("GET", acsURL, bytes.NewBuffer(body))
		//		if err != nil {
		//			print(err)
		//			return
		//		}
		//
		//		res, err := client.Do(req)
		//		if err != nil {
		//			print(err)
		//			return
		//		}
		//
		//		defer res.Body.Close()
		//
		//		//print("got body")
		//
		//		content, err = ioutil.ReadAll(res.Body)
		//		if err != nil {
		//			print(err)
		//			return
		//		}
		//
		//
		//		if string(content) == "" {
		//			print("empty content \n")
		//		} else {
		//			print(fmt.Sprintf("\n %s", string(content)))
		//			i+= 1
		//		}
		//
		//	}
		//
		//	print("returning from goroutine")
		//
		//}(acsURL)

	}

	time.Sleep(1*time.Minute)
	return nil, nil
}

func cacheCredential(cred *v1beta1.ExecCredential, is string) error {
	return nil
}

func runCredential(ctx *cli.Context) error {
	args := ctx.Args()
	if len(args) != 2 {
		return fmt.Errorf("incorrect args, server and user id required")
	}
	print(args)

	server := args[0]
	id := args[1]

	cachedCred, err := loadCachedCredential(id)
	if err != nil {
		print(fmt.Errorf("LoadToken: %v", err))
	}

	if cachedCred != nil {
		return json.NewEncoder(os.Stdout).Encode(cachedCred)
	}

	newCred, err := loginAndGenerateCred(server, id)
	if err != nil {
		return err
	}

	if err := cacheCredential(newCred, id); err != nil {
		print(fmt.Errorf("CacheToken: %v", err))
	}

	return json.NewEncoder(os.Stdout).Encode(newCred)

	//fmt.Print("%s%s", username, password)
	//return nil

	//fmt.Print("helloWorld")
	//return nil

	//url := fmt.Sprintf("%s/v3-public/adfsProviders/adfs?action=login", c.URL)
	//
	//fmt.Println(url)

	//var jsonStr2 = []byte(fmt.Sprintf(`{"finalRedirectUrl":"%s"}`, c.URL))
	//fmt.Print(string(jsonStr2))
	//
	//req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr2))
	//if err != nil {
	//	return err
	//}
	//
	//tr := &http.Transport{
	//	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	//}
	//
	//client := &http.Client{Transport: tr}
	//
	//res, err := client.Do(req)
	//if err != nil {
	//	return err
	//}
	//
	//defer res.Body.Close()
	//
	//content, err := ioutil.ReadAll(res.Body)
	//if err != nil {
	//	return err
	//}
	//
	//fmt.Print(string(content))

	//type SamlLoginOutput struct {
	//	IdpRedirectURL string `json:"idpRedirectUrl"`
	//}
	//
	//var output *v3public.SamlLoginOutput
	////
	//err = json.Unmarshal(content, &output)
	//if err != nil {
	//	return err
	//}
	//
	//fmt.Print(output.IdpRedirectURL)

	//fmt.Print("hey,asking for input:")

	test := v1beta1.ExecCredential{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ExecCredential",
			APIVersion: v1beta1.SchemeGroupVersion.String(),
		},
		Status: &v1beta1.ExecCredentialStatus{},
	}
	test.Status.Token = "kubeconfig-user-qdzhg.c-zdr26:xm4p7zvcwjdkwpfdxsvvxbrnp5ztxmvh2wx8zv6vhxqtq6mst2dbgt"
	enc, _ := json.Marshal(test)
	fmt.Print(string(enc))

	return nil
}

func KubectlCommand() cli.Command {
	return cli.Command{
		Name:            "kubectl",
		Usage:           "Run kubectl commands",
		Description:     "Use the current cluster context to run kubectl commands in the cluster",
		Action:          runKubectl,
		SkipFlagParsing: true,
	}
}

func runKubectl(ctx *cli.Context) error {
	args := ctx.Args()
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
		return cli.ShowCommandHelp(ctx, "kubectl")
	}

	path, err := exec.LookPath("kubectl")
	if err != nil {
		return fmt.Errorf("kubectl is required to be set in your path to use this "+
			"command. See https://kubernetes.io/docs/tasks/tools/install-kubectl/ "+
			"for more info. Error: %s", err.Error())
	}

	c, err := GetClient(ctx)
	if err != nil {
		return err
	}

	cluster, err := getClusterByID(c, c.UserConfig.FocusedCluster())
	if err != nil {
		return err
	}

	config, err := c.ManagementClient.Cluster.ActionGenerateKubeconfig(cluster)
	if err != nil {
		return err
	}

	tmpfile, err := ioutil.TempFile("", "rancher-")
	if err != nil {
		return err
	}
	defer os.Remove(tmpfile.Name())

	_, err = tmpfile.Write([]byte(config.Config))
	if err != nil {
		return err
	}

	err = tmpfile.Close()
	if err != nil {
		return err
	}

	kubeLocationFlag := "--kubeconfig=" + tmpfile.Name()

	combinedArgs := []string{kubeLocationFlag}
	combinedArgs = append(combinedArgs, ctx.Args()...)

	cmd := exec.Command(path, combinedArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	err = cmd.Run()
	if err != nil {
		return err
	}
	return nil
}
