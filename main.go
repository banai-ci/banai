package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/banai-ci/banai/commands/archive"
	"github.com/banai-ci/banai/commands/fs"
	"github.com/banai-ci/banai/commands/gitclient"
	hashImpl "github.com/banai-ci/banai/commands/hash"
	"github.com/banai-ci/banai/commands/httpclient"
	secret "github.com/banai-ci/banai/commands/secrets"
	"github.com/banai-ci/banai/commands/shell"
	"github.com/banai-ci/banai/infra"
	"github.com/dop251/goja"
)

const (
	defaultScriptFileName = "Banaifile"
	mainFuncName          = "main"
)

func loadScript(fileName string) string {
	b, e := ioutil.ReadFile(fileName)
	if e != nil {
		if os.IsNotExist(e) {
			panic(fmt.Sprint("Script file: " + fileName + ", not found"))
		} else {
			panic(e)
		}

	}
	return string(b)
}

func loadSecrets(secretsFile string, b *infra.Banai) (err error) {
	if secretsFile == "" {
		return nil
	}
	var fileContent []byte
	fileContent, err = ioutil.ReadFile(secretsFile)
	if err != nil {
		return
	}

	var secretsRootItem map[string]interface{}
	err = json.Unmarshal(fileContent, &secretsRootItem)
	if err != nil {
		return
	}

	var intr interface{}
	var ok bool
	if intr, ok = secretsRootItem["secrets"]; !ok {
		return
	}

	var secretObjectInter map[string]interface{}
	secretsInterfaces := intr.([]interface{})
	var secretTypeInter interface{}
	var secretType string

	for _, secretInterface := range secretsInterfaces {
		secretObjectInter = secretInterface.(map[string]interface{})
		secretTypeInter, ok = secretObjectInter["type"]
		secretType = secretTypeInter.(string)
		if ok {
			switch secretType {
			case "text":
				b.AddStringSecret(secretObjectInter["id"].(string), secretObjectInter["text"].(string))
			case "ssh":
				b.AddSSHWithPrivate(secretObjectInter["id"].(string),
					secretObjectInter["user"].(string),
					secretObjectInter["privateKey"].(string),
					secretObjectInter["passphrase"].(string))
			case "userpass":
				b.AddUserPassword(secretObjectInter["id"].(string),
					secretObjectInter["user"].(string),
					secretObjectInter["password"].(string))
			}
		}
	}

	return
}

func runBuild(scriptFileName string, param infra.BanaiParams, funcCalls []string, secretsFile string) (done chan infra.BanaiResult, abort chan bool, startErr error) {
	abort = make(chan bool)
	done = make(chan infra.BanaiResult)

	var b = infra.NewBanai(param)
	var runReturnedValue infra.BanaiResult
	b.PanicOnError(loadSecrets(secretsFile, b))
	//--------- go routin for reporting log out an
	go func() {
		defer func() {
			if err := recover(); err != nil {
				b.Logger.Error(err)
				b.Logger.Error("Script execution exit with error !!!!!")
			}
			userResult := b.Jse.Get(infra.GlobalExecutionResultObjectName)
			runReturnedValue = infra.GenerateBanaiResult(true, nil, b.Result.Params, userResult)
			b.Close()
			done <- runReturnedValue

		}()

		go func() {
			<-abort
			err := fmt.Errorf("Abort execution")

			b.Jse.Interrupt(err)
		}()
		if scriptFileName == defaultScriptFileName {
			_, err := os.Stat(scriptFileName)
			if os.IsNotExist(err) {
				scriptFileName = defaultScriptFileName + ".js"
			}
		}
		program, err := goja.Compile(scriptFileName, loadScript(scriptFileName), false)
		if err != nil {
			runReturnedValue = infra.GenerateBanaiResult(false, err, b.Result.Params, nil)
			panic(fmt.Sprintln("Failed to compile script ", scriptFileName, err))
		}

		shell.RegisterJSObjects(b)
		archive.RegisterJSObjects(b)
		fs.RegisterJSObjects(b)
		hashImpl.RegisterJSObjects(b)
		httpclient.RegisterJSObjects(b)
		secret.RegisterJSObjects(b)
		gitclient.RegisterJSObjects(b)

		_, err = b.Jse.RunProgram(program)

		if err != nil {
			runReturnedValue = infra.GenerateBanaiResult(false, err, b.Result.Params, nil)
			return
		}

		var funcNames = []string{"main"}

		if len(funcCalls) > 0 {
			funcNames = funcCalls
		}

		for _, fn := range funcNames {
			_, ok := goja.AssertFunction(b.Jse.Get(fn))
			if !ok {
				err := fmt.Errorf("function %s not found", fn)
				b.Logger.Panic(err)
			}
			_, err = b.Jse.RunString(fmt.Sprintf("%s()", fn))
			if jserr, ok := err.(*goja.Exception); ok {
				err := fmt.Errorf("Failure at execution %s", jserr)
				b.Logger.Panic(err)
				break
			}

		}

	}()
	return
}

type multiVal map[string]string

func (m multiVal) String() string {
	params := make([]string, 0)
	for k, v := range m {
		params = append(params, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(params, ",")
}
func (m *multiVal) Set(p string) error {
	p = strings.TrimSpace(p)
	if p == "" {
		return nil
	}
	eqIdx := strings.Index(p, "=")
	if eqIdx < 0 {
		(*m)[p] = ""
	} else {
		(*m)[p[:eqIdx]] = p[eqIdx+1:]
	}
	return nil
}

func main() {

	var scriptFileName = defaultScriptFileName
	var funcCalls []string
	var isAgent bool
	var secretsFile string
	var params multiVal

	flag.StringVar(&scriptFileName, "f", defaultScriptFileName, "Set script to run. Default is Banaifile")
	flag.StringVar(&scriptFileName, "file", defaultScriptFileName, "Set script to run. Default is Banaifile")
	flag.BoolVar(&isAgent, "agent", false, "true if banai is run as agent")
	flag.StringVar(&secretsFile, "s", "", "A secrets file. See _examples/secret-file.json")
	flag.StringVar(&secretsFile, "secrets", "", "A secrets file. See _examples/secret-file.json")
	flag.Var(&params, "param", "Pass params to the banai. A param value is in the form of name=value. The parameter can be passed many time")
	flag.Parse()

	funcCalls = flag.Args()

	//----------- converting
	if !isAgent {
		doneCH, _, _ := runBuild(scriptFileName, infra.BanaiParams(params), funcCalls, secretsFile)

		exitValue := <-doneCH
		if !exitValue.Complete {
			fmt.Println("Exit running Banaifile", scriptFileName, " with error !!!\n%s ", exitValue.ErrorMessage)
		} else {
			fmt.Println("Done running Banaifile", scriptFileName)
		}

	}

}
