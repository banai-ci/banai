package sshutils

import (
	"fmt"
	"io"
	"net"

	"golang.org/x/crypto/ssh"
)

type connectionEndpoint struct {
	Host string
	Port int
}

func (endpoint *connectionEndpoint) String() string {
	return fmt.Sprintf("%s:%d", endpoint.Host, endpoint.Port)
}

//SSHtunnel define local remote server and remote resource to use
type SSHtunnel struct {
	Local  *connectionEndpoint
	Server *connectionEndpoint
	Remote *connectionEndpoint

	Config       *ssh.ClientConfig
	listener     net.Listener
	stopListener bool
}

//Start listening to incomming connectiopn on local host and forward them to the remote tunnel
func (tunnel *SSHtunnel) Start() error {

	var err error
	tunnel.listener, err = net.Listen("tcp", tunnel.Local.String())
	if err != nil {
		return err
	}

	go func() {
		for !tunnel.stopListener {
			conn, err := tunnel.listener.Accept()
			if err == nil {
				go tunnel.forward(conn)
			}

		}
	}()

	return nil
}

//Close the tunnel and release any resources
func (tunnel *SSHtunnel) Close() {
	tunnel.stopListener = true
	if tunnel.listener != nil {
		tunnel.listener.Close()
	}
}

func (tunnel *SSHtunnel) forward(localConn net.Conn) {
	serverConn, err := ssh.Dial("tcp", tunnel.Server.String(), tunnel.Config)
	if err != nil {
		fmt.Printf("Server dial error: %s\n", err)
		return
	}

	remoteConn, err := serverConn.Dial("tcp", tunnel.Remote.String())
	if err != nil {
		fmt.Printf("Remote dial error: %s\n", err)
		return
	}

	copyConn := func(writer, reader net.Conn) {
		defer writer.Close()
		defer reader.Close()

		_, err := io.Copy(writer, reader)
		if err != nil {
			fmt.Printf("io.Copy error: %s", err)
		}
	}

	go copyConn(localConn, remoteConn)
	go copyConn(remoteConn, localConn)
}

//CreateTunnel a tunnel via an intermediateServer
func CreateTunnel(localPort int, resourceHost string, resourcePort int, intermediateServerHost string, intermediateServerPort int, sshConf *ssh.ClientConfig) (*SSHtunnel, error) {
	localEndpoint := &connectionEndpoint{
		Host: "localhost",
		Port: localPort,
	}
	remoteEndpoint := &connectionEndpoint{
		Host: resourceHost,
		Port: resourcePort,
	}
	serverEndpoint := &connectionEndpoint{
		Host: intermediateServerHost,
		Port: intermediateServerPort,
	}

	tunnel := &SSHtunnel{
		Config: sshConf,
		Local:  localEndpoint,
		Server: serverEndpoint,
		Remote: remoteEndpoint,
	}

	tunnel.Start()
	return tunnel, nil
}
