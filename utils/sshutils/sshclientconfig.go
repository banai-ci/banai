package sshutils

import (
	"io/ioutil"
	"net"

	"golang.org/x/crypto/ssh"
)

//CreateFromUserPassword connect via user password
func CreateFromUserPassword(user, pwd string) *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(pwd),
		},
		HostKeyCallback: ssh.HostKeyCallback(func(hostname string, remote net.Addr, key ssh.PublicKey) error { return nil }),
	}
}

//CreateFromPrivateKeyContent create using private key content
func CreateFromPrivateKeyContent(user string, privateKey []byte, passphrase ...string) (*ssh.ClientConfig, error) {
	var signer ssh.Signer
	var err error

	if passphrase != nil && passphrase[0] != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(privateKey, []byte(passphrase[0]))

	} else {
		signer, err = ssh.ParsePrivateKey(privateKey)
	}

	if err != nil {
		return nil, err
	}

	return &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.HostKeyCallback(func(hostname string, remote net.Addr, key ssh.PublicKey) error { return nil }),
	}, nil
}

//CreateFromPrivateKeyFile create using private key from file
func CreateFromPrivateKeyFile(user string, privateKeyFile string, passfphrase ...string) (*ssh.ClientConfig, error) {
	key, err := ioutil.ReadFile(privateKeyFile)
	if err != nil {
		return nil, err
	}
	return CreateFromPrivateKeyContent(user, key, passfphrase...)
}
