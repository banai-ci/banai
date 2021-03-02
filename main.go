package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

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

func runBuild(scriptFileName string, funcCalls []string, secretsFile string) (done chan goja.Value, abort chan bool, startErr error) {
	abort = make(chan bool)
	done = make(chan goja.Value)

	var b = infra.NewBanai()
	var runReturnedValue goja.Value
	b.PanicOnError(loadSecrets(secretsFile, b))
	//--------- go routin for reporting log out an
	go func() {
		defer func() {
			if err := recover(); err != nil {
				b.Logger.Error(err)
				b.Logger.Error("Script execution exit with error !!!!!")
			}
			b.Close()
			done <- runReturnedValue

		}()

		go func() {
			<-abort
			b.Jse.Interrupt("Abort execution")
		}()
		if scriptFileName == defaultScriptFileName {
			_, err := os.Stat(scriptFileName)
			if os.IsNotExist(err) {
				scriptFileName = defaultScriptFileName + ".js"
			}
		}
		program, err := goja.Compile(scriptFileName, loadScript(scriptFileName), false)
		if err != nil {

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
			runReturnedValue = b.Jse.ToValue(fmt.Errorf("Failed to run program %s", err))
			return
		}

		var funcNames = []string{"main"}

		if len(funcCalls) > 0 {
			funcNames = funcCalls
		}

		for _, fn := range funcNames {
			_, ok := goja.AssertFunction(b.Jse.Get(fn))
			if !ok {
				b.Logger.Panic(fmt.Errorf("function %s not found", fn))
			}
			_, err = b.Jse.RunString(fmt.Sprintf("%s()", fn))
			if jserr, ok := err.(*goja.Exception); ok {
				b.Logger.Error("Failure at execution ", jserr)
				runReturnedValue = b.Jse.ToValue(jserr)
				break
			}

		}

	}()
	return
}

func main() {

	var scriptFileName = defaultScriptFileName
	var funcCalls []string
	var isAgent bool
	var secretsFile string

	flag.StringVar(&scriptFileName, "f", defaultScriptFileName, "Set script to run. Default is Banaifile")
	flag.StringVar(&scriptFileName, "file", defaultScriptFileName, "Set script to run. Default is Banaifile")
	flag.BoolVar(&isAgent, "agent", false, "true if banai is run as agent")
	flag.StringVar(&secretsFile, "s", "", "A secrets file. See _examples/secret-file.json")
	flag.StringVar(&secretsFile, "secrets", "", "A secrets file. See _examples/secret-file.json")
	flag.Parse()

	funcCalls = flag.Args()

	//----------- converting
	if !isAgent {
		doneCH, _, _ := runBuild(scriptFileName, funcCalls, secretsFile)

		exitValue := <-doneCH
		if exitValue != nil {
			fmt.Println("Exit running Banaifile", scriptFileName, " Last result was ", exitValue)
		} else {
			fmt.Println("Exit running Banaifile", scriptFileName)
		}

	}

}
