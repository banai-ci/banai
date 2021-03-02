package gitclient

import (
	"fmt"
	"strings"

	"github.com/banai-ci/banai/infra"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/plumbing/transport/ssh"
)

var banai *infra.Banai

//GitCloneOptions Auth to connect with git
type GitCloneOptions struct {
	SecretID string //Banai secretID.
	User     string
	Password string
}

func cloneNoCredentials(sourceURL string, targetFolder string) error {
	_, err := git.PlainClone(targetFolder, false, &git.CloneOptions{
		URL: sourceURL,
	})
	return err
}

func cloneUserPassword(sourceURL, targetFolder, user, password string) error {
	_, err := git.PlainClone(targetFolder, false, &git.CloneOptions{
		Auth: &http.BasicAuth{
			Username: user, // yes, this can be anything except an empty string
			Password: password,
		},
		URL: sourceURL,
	})
	return err
}

func cloneWithSSH(sourceURL, targetFolder, privateKeyFile, passphrase string) error {
	publicKeys, err := ssh.NewPublicKeysFromFile("git", privateKeyFile, passphrase)
	if err != nil {
		return err
	}
	_, err = git.PlainClone(targetFolder, false, &git.CloneOptions{
		Auth: publicKeys,
		URL:  sourceURL,
	})

	return err
}

func gitClone(originURL string, targetFolder string, cloneOpt ...GitCloneOptions) {
	targetFolder = strings.TrimSpace(targetFolder)
	if targetFolder == "" {
		targetFolder = "."
	}

	if cloneOpt != nil && len(cloneOpt) > 0 {
		var err = fmt.Errorf("No credentials were found")
		cloneOptions := cloneOpt[0]
		if strings.TrimSpace(cloneOptions.SecretID) != "" {
			si, err := banai.GetSecret(cloneOptions.SecretID)
			banai.PanicOnError(err)
			switch si.GetType() {
			case infra.SecretTypeUserPass:
				up := si.(infra.UserPassword)
				err = cloneUserPassword(originURL, targetFolder, up.User, up.Password)
			case infra.SecretTypeSSH:
				sshInfo := si.(infra.SSHWithPrivate)
				err = cloneWithSSH(originURL, targetFolder, sshInfo.PrivatekeyFile, sshInfo.Passfrase)
			} //switch

		}
		banai.PanicOnError(err)
	} else {

		banai.PanicOnError(cloneNoCredentials(originURL, targetFolder))
	}

}

//RegisterJSObjects register git objects
func RegisterJSObjects(b *infra.Banai) {
	banai = b

	banai.Jse.GlobalObject().Set("gitClone", gitClone)
}
