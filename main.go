package main

import (
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

func runBuild(scriptFileName string, params infra.BanaiParams, funcCalls []string, secretsFile string) (done chan infra.BanaiResult, abort chan bool, startErr error) {
	abort = make(chan bool)
	done = make(chan infra.BanaiResult)
	var b *infra.Banai
	b, startErr = infra.NewBanai(params, secretsFile)
	var runReturnedValue infra.BanaiResult

	b.Logger.Info(fmt.Sprintf("Created banai with paramets: %v", params))

	//--------- go routin for reporting log out an
	go func() {
		defer func() {
			if err := recover(); err != nil {
				switch err {
				case infra.ErrScriptDone:
					userResult := b.Jse.Get(infra.GlobalExecutionResultObjectName)
					runReturnedValue = infra.GenerateBanaiResult(true, nil, b.Result.Params, userResult)
				case infra.ErrScriptAbort:
					userResult := b.Jse.Get(infra.GlobalExecutionResultObjectName)
					runReturnedValue = infra.GenerateBanaiResult(false, fmt.Errorf("Script called abort"), b.Result.Params, userResult)
					b.Logger.Error("Script execution aborted !!!!!")
				default:
					runReturnedValue = infra.GenerateBanaiResult(false, fmt.Errorf("%s", err), b.Result.Params, nil)
					b.Logger.Error("Script execution exit due to Exception !!!!!")
				}

			} else {
				userResult := b.Jse.Get(infra.GlobalExecutionResultObjectName)
				runReturnedValue = infra.GenerateBanaiResult(true, nil, b.Result.Params, userResult)
			}

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
				b.Logger.Panic(jserr)
				break
			}

			if interr, ok := err.(*goja.InterruptedError); ok {
				interruptString := fmt.Sprint(interr.Value())
				switch interruptString {
				case infra.ErrScriptAbort.Error():
					panic(infra.ErrScriptAbort)
				case infra.ErrScriptDone.Error():
					panic(infra.ErrScriptDone)
				default:
					panic(err)
				}
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
	var paramsFile string //Path to json file that has the structure infra.BanaiParams

	flag.StringVar(&scriptFileName, "f", defaultScriptFileName, "Set script to run. Default is Banaifile")
	flag.StringVar(&scriptFileName, "file", defaultScriptFileName, "Set script to run. Default is Banaifile")
	flag.BoolVar(&isAgent, "agent", false, "true if banai is run as agent")
	flag.StringVar(&secretsFile, "s", "", "A secrets file. See _examples/secret-file.json")
	flag.StringVar(&secretsFile, "secrets", "", "A secrets file. See _examples/secret-file.json")
	flag.StringVar(&paramsFile, "p", "", "A json file holding the parameter of banai")
	flag.Parse()

	funcCalls = flag.Args()

	//----------- converting
	if !isAgent {
		var params infra.BanaiParams
		var err error
		if paramsFile != "" {
			params, err = infra.LoadParameters(paramsFile)
			if err != nil {
				panic(fmt.Sprintf("Failed to load parameters from file %s. Error: %s", paramsFile, err))
			}
		}
		doneCH, _, _ := runBuild(scriptFileName, params, funcCalls, secretsFile)

		exitValue := <-doneCH
		if !exitValue.Complete {
			fmt.Println("Exit running Banaifile", scriptFileName, " with error !!!", exitValue.ErrorMessage)
		} else {
			fmt.Println("Done running Banaifile script ", scriptFileName)
		}

	}

}
