package shellutils

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"time"

	"github.com/banai-ci/banai/utils/sshutils"
	"golang.org/x/crypto/ssh"
)

//ShellResult reponse of the shell action
type ShellResult struct {
	Code int    `json:"code,omitempty"`
	Out  string `json:"out,omitempty"`
	Err  string `json:"err,omitempty"`
}

//CommandOptions how to run the a shell command
type CommandOptions struct {
	Shell    string   `json:"shell,omitempty"`
	In       string   `json:"in,omitempty"`
	Ins      []string `json:"ins,omitempty"`
	Env      []string `json:"env,omitempty"`
	Timeout  int      `json:"timeout,omitempty"`
	SecretID string   `json:"secretId,omitempty"`
}

//DefaultBashCommandOptions default for running with bash
func DefaultBashCommandOptions() CommandOptions {
	ret := CommandOptions{}
	ret.Shell = "/bin/bash"
	return ret
}

//RunShellCommand execute a command using the shell
func RunShellCommand(commandToRun string, cmdOpt ...CommandOptions) (*ShellResult, error) {
	if cmdOpt == nil {
		cmdOpt = []CommandOptions{DefaultBashCommandOptions()}
	} else {
		if cmdOpt[0].Shell == "" {
			cmdOpt[0].Shell = "/bin/bash"
		}

	}

	var finalCommand = make([]string, 0)

	var shellCmd = cmdOpt[0].Shell

	finalCommand = append(finalCommand, "-c")
	finalCommand = append(finalCommand, commandToRun)

	var command *exec.Cmd
	if cmdOpt != nil && cmdOpt[0].Timeout > 0 {
		ctx, cancelFunc := context.WithTimeout(context.Background(), time.Duration(cmdOpt[0].Timeout)*time.Second)
		defer cancelFunc()
		command = exec.CommandContext(ctx, shellCmd, finalCommand...)
	} else {
		command = exec.Command(shellCmd, finalCommand...)
	}

	command.Env = append(command.Env, os.Environ()...)
	if cmdOpt[0].Env != nil {
		command.Env = append(command.Env, cmdOpt[0].Env...)
	}

	cmdStdOutPipe, _ := command.StdoutPipe()
	cmdStdErrPipe, _ := command.StderrPipe()
	procWriter, _ := command.StdinPipe()

	var err error
	err = command.Start()
	if err != nil {
		return nil, err
	}

	if cmdOpt != nil && cmdOpt[0].In != "" {
		procWriter.Write([]byte(cmdOpt[0].In))
		procWriter.Write([]byte("\n"))
	}
	if cmdOpt != nil && cmdOpt[0].Ins != nil {
		for _, line := range cmdOpt[0].Ins {
			procWriter.Write([]byte(line))
			procWriter.Write([]byte("\n"))
		}
	}
	var buf []byte
	ret := &ShellResult{}
	buf, err = ioutil.ReadAll(cmdStdOutPipe)
	if err == nil {
		ret.Out = string(buf)
	}
	buf, err = ioutil.ReadAll(cmdStdErrPipe)
	if err == nil {
		ret.Err = string(buf)
	}

	err = command.Wait()
	if err == nil {
		ret.Code = 0
	} else {
		if exiterr, ok := err.(*exec.ExitError); ok {
			ret.Code = exiterr.ExitCode()
		} else {
			ret.Code = 1
		}

	}

	return ret, nil
}

//ShellSSHConfig connection configuration
type ShellSSHConfig struct {
	Address        string `json:"address,omitempty"`
	User           string `json:"user,omitempty"`
	Password       string `json:"password,omitempty"`
	PrivateKeyFile string `json:"privateKeyFile,omitempty"`
	Passphrase     string `json:"passphrase,omitempty"`
	SecretID       string `json:"secretId,omitempty"`
}

//RunRemoteShell execute a command on remote shell
func RunRemoteShell(sshConf ShellSSHConfig, cmd string) (*ShellResult, error) {
	var sshClientConf *ssh.ClientConfig
	var e error

	if sshConf.Address == "" {
		return nil, fmt.Errorf("sshConfig target host Address not set")
	}
	if sshConf.User == "" {
		return nil, fmt.Errorf("sshConfig User not set")
	}

	if sshConf.Password != "" {
		sshClientConf = sshutils.CreateFromUserPassword(sshConf.User, sshConf.Password)
	} else {
		if sshConf.PrivateKeyFile != "" {
			sshClientConf, e = sshutils.CreateFromPrivateKeyFile(sshConf.User, sshConf.PrivateKeyFile, sshConf.Passphrase)
			if e != nil {
				return nil, e
			}
		}
	}

	var client *sshutils.Client
	client, e = sshutils.Dial(sshConf.Address, sshClientConf)
	if e != nil {
		return nil, e
	}
	defer client.Close()

	stdout, stderr, e := client.Cmd(cmd)
	if e != nil {
		return nil, e
	}

	if len(stderr) > 0 {
		return &ShellResult{
			Code: 1,
			Out:  string(stdout),
		}, nil
	}

	return &ShellResult{
		Code: 0,
		Out:  string(stdout),
	}, nil
}
