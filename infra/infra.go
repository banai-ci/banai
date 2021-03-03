package infra

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/banai-ci/banai/utils/fsutils"
	"github.com/dop251/goja"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

//ErrSecretNotFound return when the secret was not found in secret manager
var ErrSecretNotFound = errors.New("Secret not found")

//ErrScriptAbort Called when script used abort command to terminate execution
var ErrScriptAbort = errors.New("Banai Script Aborted")

//ErrScriptDone Called when script uses done to signal that execution is done
var ErrScriptDone = errors.New("Banai Script Done")

//GlobalExecutionResultObjectName The name of the Javascript Global object that holds the Result field of BanaiResult
const GlobalExecutionResultObjectName = "banaiResult"

//BanaiParamTypeString BanaiParamInfo.Value is a string
const BanaiParamTypeString = "string" //A string

//BanaiParamTypeList BanaiParamInfo.Value is a list of string
const BanaiParamTypeList = "list" // List of strings

//BanaiParamData The value of
type BanaiParamData struct {
	Type  string      `json:"type,omitempty"`  // One of BanaiParamType values
	Value interface{} `json:"value,omitempty"` //Align with the type
}

//BanaiParams are passed to banai on creation
type BanaiParams map[string]BanaiParamData

//LoadParameters loads banai parameters from json file
func LoadParameters(parameterFilePath string) (param BanaiParams, err error) {
	var data []byte
	data, err = ioutil.ReadFile(parameterFilePath)
	if err != nil {
		return
	}
	err = json.Unmarshal(data, &param)

	return
}

//BanaiResult is a return object of banai. This value is set by the shell commands: done or exit
//If the user does not call done or exit explicitrly than this object is created by the Banai object in the following way:
//If execution done with no errors, BanaiResult.Complete is true and BanaiResult.Result is nil.
//If exceution interrupted with call to exit. BanaiResult.Comlete is false, ErrorMessage will be filled by the exception text. result is nil
type BanaiResult struct {
	Complete     bool              `json:"complete,omitempty"`     //true if the execution ended normaly
	ErrorMessage string            `json:"errorMessage,omitempty"` //In case of exception, this will hold the string of the error
	Env          map[string]string `json:"env,omitempty"`          //A map of key values filled by the environment variables used when running the banai.
	Params       BanaiParams       `json:"params,omitempty"`       //The parameters Banai was started, This is done by using --param flag
	Result       interface{}       `json:"result,omitempty"`       //An object that returned by the user. This value is filled when
}

//Banai banai main struct
type Banai struct {
	Jse          *goja.Runtime
	TmpDir       string
	Logger       *logrus.Logger
	stashFolder  string
	secretFolder string
	secrets      map[string]SecretInfo
	Result       BanaiResult
}

//GenerateBanaiResult create a result object
func GenerateBanaiResult(complete bool, err error, params BanaiParams, resultObject interface{}) BanaiResult {
	ret := BanaiResult{
		Complete: complete,
	}

	if err != nil {
		ret.ErrorMessage = fmt.Sprint(err)
	}
	var eqIdx int
	ret.Env = make(map[string]string)

	//extract environment varaibles
	for _, env := range os.Environ() {
		env = strings.TrimSpace(env)
		eqIdx = strings.Index(env, "=")
		if eqIdx < 0 {
			ret.Env[env] = ""
		} else {
			ret.Env[env[:eqIdx]] = env[eqIdx+1:]
		}
	} //for

	ret.Params = BanaiParams{}
	ret.Result = resultObject

	return ret
}

func (b *Banai) abortExecution(returnObject interface{}) {
	if returnObject != nil {
		b.Jse.GlobalObject().Set(GlobalExecutionResultObjectName, b.Jse.ToValue(returnObject))
	}
	b.Jse.Interrupt(ErrScriptAbort)
}

func (b *Banai) doneExecution(returnObject interface{}) {
	if returnObject != nil {
		b.Jse.GlobalObject().Set(GlobalExecutionResultObjectName, b.Jse.ToValue(returnObject))
	}
	b.Jse.Interrupt(ErrScriptDone)
}

//NewBanai create new banai struct object
func NewBanai(params BanaiParams, secretFilePath string) (*Banai, error) {
	ret := &Banai{
		Jse:     goja.New(),
		Logger:  logrus.New(),
		secrets: make(map[string]SecretInfo),
	}
	ret.Jse.SetFieldNameMapper(goja.TagFieldNameMapper("json", true))
	ret.TmpDir, _ = filepath.Abs("./.banai")
	ret.stashFolder = filepath.Join(ret.TmpDir, "stash")
	ret.secretFolder = filepath.Join(ret.TmpDir, "sec")
	os.RemoveAll(ret.stashFolder)
	os.MkdirAll(ret.stashFolder, 0700)
	os.RemoveAll(ret.secretFolder)
	os.MkdirAll(ret.secretFolder, 0700)

	ret.Jse.GlobalObject().Set("abort", ret.abortExecution)
	ret.Jse.GlobalObject().Set("done", ret.doneExecution)

	if secretFilePath != "" {
		secrets, err := loadSecrestFromFile(secretFilePath)
		if err != nil {
			return nil, err
		}
		ret.secrets = secrets
	}

	ret.Result = GenerateBanaiResult(false, nil, params, nil)

	return ret, nil
}

//PanicOnError return Value typed panic so javascript will get exception
func (b Banai) PanicOnError(e error, t ...string) {
	if e != nil {
		var msg string
		if t != nil {
			msg = fmt.Sprintf("%s %s", t, e)
			b.Logger.Error(msg)
			panic(b.Jse.ToValue(msg))

		} else {
			msg = fmt.Sprint(e)
			b.Logger.Error(msg)
			panic(b.Jse.ToValue(msg))
		}

	}
}

//Close should be call at the end of using banai to remove all allocated resource during banai execution
func (b Banai) Close() {
	os.RemoveAll(b.TmpDir)

}

//*********************************************************************************

//Save stashs file CONTENT
func (b Banai) Save(fileName string) (string, error) {
	abs, e := filepath.Abs(fileName)
	if e != nil {
		return "", e
	}
	stashID := uuid.NewString()

	e = fsutils.CopyfsItem(abs, stashID)
	if e != nil {
		return "", e
	}
	return stashID, nil
}

//Load restore the CONTENT of a previously stashed file
func (b Banai) Load(stashID string) ([]byte, error) {
	path := filepath.Join(b.stashFolder, stashID)
	_, e := os.Stat(path)
	if e != nil {
		return nil, e
	}

	f, e := ioutil.ReadFile(path)
	if e != nil {
		return nil, e
	}

	return f, nil

}

//*********************************************************************************

func loadSecrestFromFile(filePath string) (map[string]SecretInfo, error) {
	ret := make(map[string]SecretInfo)
	var rawSecrets map[string]map[string]interface{}

	b, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	json.Unmarshal(b, &rawSecrets)

	var ok bool
	var secRawType string
	var typeInterface interface{}
	for secretID, secretInfo := range rawSecrets {
		typeInterface, ok = secretInfo["type"]
		if ok {
			secRawType, ok = typeInterface.(string)
			var valInter interface{}
			if ok {
				switch secRawType {
				case SecretTypeText:

					if valInter, ok = secretInfo["text"]; ok {
						ts := TextSecret{}
						ts.Text = valInter.(string)
						ret[secretID] = ts
					}

				case SecretTypeSSH:
					sshSec := SSHWithPrivate{}
					if valInter, ok = secretInfo["user"]; ok {
						sshSec.User = valInter.(string)
					}
					if valInter, ok = secretInfo["privateKeyFile"]; ok {
						sshSec.PrivateKeyFile = valInter.(string)
					}
					if valInter, ok = secretInfo["passphrase"]; ok {
						sshSec.Passphrase = valInter.(string)
					}

					ret[secretID] = sshSec
				case SecretTypeUserPass:
					upSec := UserPassword{}
					if valInter, ok = secretInfo["user"]; ok {
						upSec.User = valInter.(string)
					}
					if valInter, ok = secretInfo["password"]; ok {
						upSec.Password = valInter.(string)
					}
					ret[secretID] = upSec
				} //switch
			}
		}
	}

	return ret, nil
}

//*********************************************************************************

//SecretTypeText secret of type text
const SecretTypeText = "text"

//SecretTypeSSH secret of type ssh
const SecretTypeSSH = "ssh"

//SecretTypeUserPass secret of type username password
const SecretTypeUserPass = "userpass"

//SecretInfo Base interface of returned secrets
type SecretInfo interface {
	GetType() string
}

//TextSecret return string secret
type TextSecret struct {
	Text string `json:"text,omitempty"`
}

//GetType type of secret
func (t TextSecret) GetType() string {
	return "text"
}

//SSHWithPrivate info to use when using ssh with private key
type SSHWithPrivate struct {
	User           string `json:"user,omitempty"`
	PrivateKeyFile string `json:"privateKeyFile,omitempty"`
	Passphrase     string `json:"passphrase,omitempty"`
}

//GetType get secret info type
func (t SSHWithPrivate) GetType() string {
	return "ssh"
}

//UserPassword info to use when using user password
type UserPassword struct {
	User     string `json:"user,omitempty"`
	Password string `json:"password,omitempty"`
}

//GetType get secret info type
func (t UserPassword) GetType() string {
	return "userpass"
}

//GetSecret add secret string
func (b Banai) GetSecret(secretID string) (SecretInfo, error) {
	v, ok := b.secrets[secretID]
	if !ok {
		return nil, ErrSecretNotFound
	}

	return v, nil
}

//*********************************************************************************
