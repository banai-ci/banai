package secrets

import (
	"fmt"

	"github.com/banai-ci/banai/infra"
)

var banai *infra.Banai

func getTextSecret(secretID string) (ret string) {
	var ok bool
	var err error
	var secret infra.SecretInfo
	secret, err = banai.GetSecret(secretID)
	banai.PanicOnError(err)

	_, ok = secret.(infra.TextSecret)
	if !ok {
		banai.PanicOnError(fmt.Errorf("Secret %s is not a Text secret", secretID))
	}
	ret = secret.(infra.TextSecret).Text
	return
}

func getSSHSecret(secretID string) (ret infra.SSHWithPrivate) {
	var ok bool
	var err error
	var secret infra.SecretInfo
	secret, err = banai.GetSecret(secretID)
	banai.PanicOnError(err)
	ret, ok = secret.(infra.SSHWithPrivate)
	if !ok {
		banai.PanicOnError(fmt.Errorf("Secret %s is not a SSH secret", secretID))
	}
	return
}

func getUserPassSecret(secretID string) (ret infra.UserPassword) {
	var ok bool
	var err error
	var secret infra.SecretInfo
	secret, err = banai.GetSecret(secretID)
	banai.PanicOnError(err)
	ret, ok = secret.(infra.UserPassword)
	if !ok {
		banai.PanicOnError(fmt.Errorf("Secret %s is not a User/password secret", secretID))
	}
	return
}

//RegisterJSObjects registers Shell objects and functions
func RegisterJSObjects(b *infra.Banai) {
	banai = b

	banai.Jse.GlobalObject().Set("getTextSecret", getTextSecret)
	banai.Jse.GlobalObject().Set("getSSHSecret", getSSHSecret)
	banai.Jse.GlobalObject().Set("getUserPassSecret", getUserPassSecret)
}
