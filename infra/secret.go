package infra

//secretStruct base interface of all secrets
type secretStruct interface {
	GetType() string //Get the type of the secret as a string

}

//SecretTypeText secret of type text
const SecretTypeText = "text"

//SecretTypeSSH secret of type ssh
const SecretTypeSSH = "ssh"

//SecretTypeUserPass secret of type username password
const SecretTypeUserPass = "userpass"

//*******************************************************************************

//secretText Save a string as secret
type secretText struct {
	Text string
}

//GetType create the object from a string
func (t secretText) GetType() string {
	return SecretTypeText
}

//*******************************************************************************

//secretSSHWithPrivate holds ssh key with private key values
type secretSSHWithPrivate struct {
	User       string
	PrivateKey string
	Passphrase string
}

//GetType create the object from a string
func (t secretSSHWithPrivate) GetType() string {
	return SecretTypeSSH
}

//*******************************************************************************

//secretSSHWithPassword holds ssh key with user and password key values
type secretUserPassword struct {
	User     string
	Password string
}

//GetType create the object from a string
func (t secretUserPassword) GetType() string {
	return SecretTypeUserPass
}

//*******************************************************************************
