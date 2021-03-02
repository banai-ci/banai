package sshutils

import (
	"bytes"
	"io"
	"os"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type remoteScriptType byte
type remoteShellType byte

const (
	cmdLine remoteScriptType = iota
	rawScript
	scriptFile

	interactiveShell remoteShellType = iota
	nonInteractiveShell
)

//An example of use:
//sshConfig=sshutils.CreateFromUserPassword("user","pwd")
//client, err := Dial("host:port", sshConfig)
//stdOut, stdErr, err := client.Cmd("ls")

// A Client implements an SSH client that supports running commands and scripts remotely.
type Client struct {
	client *ssh.Client
}

//Dial to remote server
func Dial(addr string, config *ssh.ClientConfig) (*Client, error) {
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, err
	}
	return &Client{
		client: client,
	}, nil
}

// Close closes the underlying client network connection.
func (c *Client) Close() error {
	return c.client.Close()
}

// Cmd creates a RemoteScript that can run the command on the client. The cmd string is split on newlines and each line is executed separately.
func (c *Client) Cmd(cmd string) (stdout []byte, stderr []byte, err error) {
	session, err := c.client.NewSession()
	if err != nil {
		return nil, nil, err
	}
	defer session.Close()

	var o bytes.Buffer
	var e bytes.Buffer

	session.Stdout = &o
	session.Stderr = &e

	if err := session.Run(cmd); err != nil {
		return nil, nil, err
	}
	return o.Bytes(), e.Bytes(), nil
}
func (c *Client) newSftp() (*sftp.Client, error) {
	return sftp.NewClient(c.client)
}

//UploadFile upload file to remote via ftp
func (c *Client) UploadFile(localFilePath, remoteFilePath string) error {
	local, err := os.Open(localFilePath)
	if err != nil {
		return err
	}
	defer local.Close()

	ftp, err := c.newSftp()
	if err != nil {
		return err
	}
	defer ftp.Close()

	remote, err := ftp.Create(remoteFilePath)
	if err != nil {
		return err
	}
	defer remote.Close()

	_, err = io.Copy(remote, local)
	return err
}

// Download file from remote server!
func (c *Client) Download(remoteFilePath string, localFilePath string) error {

	local, err := os.Create(localFilePath)
	if err != nil {
		return err
	}
	defer local.Close()

	ftp, err := c.newSftp()
	if err != nil {
		return err
	}
	defer ftp.Close()

	remote, err := ftp.Open(remoteFilePath)
	if err != nil {
		return err
	}
	defer remote.Close()

	if _, err = io.Copy(local, remote); err != nil {
		return err
	}

	return local.Sync()
}
