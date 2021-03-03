package shell

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/banai-ci/banai/infra"
	"github.com/banai-ci/banai/utils/shellutils"
	"github.com/banai-ci/banai/utils/sshutils"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

var logger *logrus.Logger
var banai *infra.Banai

func envToMap() map[string]string {
	var asMap = make(map[string]string)
	var eqIdx int
	for _, val := range os.Environ() {
		eqIdx = strings.IndexRune(val, '=')
		if eqIdx < 0 {
			asMap[strings.TrimSpace(val)] = "1"
		} else {
			if eqIdx == len(val)-1 {
				asMap[strings.TrimSpace(val[0:eqIdx])] = "1"
			} else {
				asMap[strings.TrimSpace(val[0:eqIdx])] = strings.TrimSpace(val[eqIdx+1:])
			}

		}
	}
	return asMap
}

func callShell(cmd string, cmdOpt ...shellutils.CommandOptions) *shellutils.ShellResult {
	var e error

	var ret *shellutils.ShellResult
	if cmdOpt != nil && len(cmdOpt) > 0 {
		opt := cmdOpt[0]
		if opt.SecretID != "" {
			secret, err := banai.GetSecret(opt.SecretID)
			banai.PanicOnError(err)
			switch secret.GetType() {
			case "ssh":
				s := secret.(infra.SSHWithPrivate)
				if opt.Env == nil {
					opt.Env = make([]string, 0)
				}
				opt.Env = append(opt.Env, fmt.Sprintf(`GIT_SSH_COMMAND="ssh -i %s -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"`, s.PrivatekeyFile))

			}

		}
		ret, e = shellutils.RunShellCommand(cmd, opt)
	} else {
		ret, e = shellutils.RunShellCommand(cmd)
	}
	banai.PanicOnError(e)

	return ret
}

func shellScript(scriptFile string, cmdOpt ...shellutils.CommandOptions) *shellutils.ShellResult {
	fileContent, e := ioutil.ReadFile(scriptFile)
	banai.PanicOnError(e)
	return callShell(string(fileContent), cmdOpt...)
}

func shell(cmd string, cmdOpt ...shellutils.CommandOptions) *shellutils.ShellResult {
	return callShell(cmd, cmdOpt...)
}

func updateSSHConfigBySecret(b *infra.Banai, secretID string, sshConf *shellutils.ShellSSHConfig) {
	if sshConf.SecretID != "" {
		v, err := b.GetSecret(sshConf.SecretID)
		if err != nil {
			b.PanicOnError(err)
		}
		switch v.GetType() {
		case "ssh":
			s := v.(infra.SSHWithPrivate)
			sshConf.Passphrase = s.Passfrase
			sshConf.PrivateKeyFile = s.PrivatekeyFile
			sshConf.User = s.User
		case "userpass":
			s := v.(infra.UserPassword)
			sshConf.User = s.User
			sshConf.Password = s.Password
		}

	}

}

func remoteshell(sshConf shellutils.ShellSSHConfig, cmd string) *shellutils.ShellResult {
	var e error

	updateSSHConfigBySecret(banai, sshConf.SecretID, &sshConf)

	var ret *shellutils.ShellResult

	ret, e = shellutils.RunRemoteShell(sshConf, cmd)
	banai.PanicOnError(e)
	return ret
}

func sshUploadFile(sshConf shellutils.ShellSSHConfig, localFile, remoteFile string) {
	var e error

	updateSSHConfigBySecret(banai, sshConf.SecretID, &sshConf)

	if sshConf.Address == "" {
		logger.Panic("sshConfig target host Address not set")
	}
	if sshConf.User == "" {
		logger.Panic("sshConfig User not set")
	}

	var sshClientConf *ssh.ClientConfig

	if sshConf.Password != "" {
		sshClientConf = sshutils.CreateFromUserPassword(sshConf.User, sshConf.Password)
	} else {
		if sshConf.PrivateKeyFile != "" {
			sshClientConf, e = sshutils.CreateFromPrivateKeyFile(sshConf.User, sshConf.PrivateKeyFile, sshConf.Passphrase)
			if e != nil {
				logger.Panic(e)
			}
		}
	}

	var client *sshutils.Client
	client, e = sshutils.Dial(sshConf.Address, sshClientConf)
	banai.PanicOnError(e)

	defer client.Close()

	e = client.UploadFile(localFile, remoteFile)
	banai.PanicOnError(e)

}

func sshDownloadFile(sshConf shellutils.ShellSSHConfig, remoteFile string, localFile string) {
	var e error

	updateSSHConfigBySecret(banai, sshConf.SecretID, &sshConf)

	if stat, e := os.Stat(remoteFile); e != nil {
		logger.Panic("Failed to open local file", e)
	} else {
		if stat.IsDir() {
			logger.Panic("Local file is directory", e)
		}
	}

	var sshClientConf *ssh.ClientConfig

	if sshConf.Address == "" {
		logger.Panic("sshConfig target host Address not set")
	}
	if sshConf.User == "" {
		logger.Panic("sshConfig User not set")
	}

	if sshConf.Password != "" {
		sshClientConf = sshutils.CreateFromUserPassword(sshConf.User, sshConf.Password)
	} else {
		if sshConf.PrivateKeyFile != "" {
			sshClientConf, e = sshutils.CreateFromPrivateKeyFile(sshConf.User, sshConf.PrivateKeyFile, sshConf.Passphrase)
			if e != nil {
				logger.Panic(e)
			}
		}
	}

	var client *sshutils.Client
	client, e = sshutils.Dial(sshConf.Address, sshClientConf)
	if e != nil {
		logger.Panic(e)
	}

	defer client.Close()

	e = client.Download(remoteFile, localFile)
	if e != nil {
		logger.Panic(e)
	}

}

func currentPath() string {
	s, err := os.Getwd()
	banai.PanicOnError(err)
	return s
}

func changeDir(dir string) {
	banai.PanicOnError(os.Chdir(dir))
}

func print(text ...interface{}) {
	fmt.Print(text...)
}

func println(text ...interface{}) {
	fmt.Println(text...)
}

func abortExecution(returnObject interface{}) {
	if returnObject != nil {
		banai.Jse.GlobalObject().Set(infra.GlobalExecutionResultObjectName, banai.Jse.ToValue(returnObject))
	}
	banai.Jse.Interrupt(infra.ErrScriptAbort)
}

func userDone(returnObject interface{}) {
	if returnObject != nil {
		banai.Jse.GlobalObject().Set(infra.GlobalExecutionResultObjectName, banai.Jse.ToValue(returnObject))
	}
	banai.Jse.Interrupt(infra.ErrScriptDone)
}

//RegisterJSObjects registers Shell objects and functions
func RegisterJSObjects(b *infra.Banai) {
	banai = b
	logger = b.Logger

	banai.Jse.GlobalObject().Set("env", envToMap())
	banai.Jse.GlobalObject().Set("pwd", currentPath)
	banai.Jse.GlobalObject().Set("cd", changeDir)
	banai.Jse.GlobalObject().Set("sh", shell)
	banai.Jse.GlobalObject().Set("shScript", shellScript)
	banai.Jse.GlobalObject().Set("rsh", remoteshell)
	banai.Jse.GlobalObject().Set("shUpload", sshUploadFile)
	banai.Jse.GlobalObject().Set("shDownload", sshDownloadFile)
	banai.Jse.GlobalObject().Set("print", print)
	banai.Jse.GlobalObject().Set("println", println)
	banai.Jse.GlobalObject().Set("abort", abortExecution)
	banai.Jse.GlobalObject().Set("done", userDone)
}
