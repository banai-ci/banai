package gitclient

import (
	"fmt"
	"os"
	"strings"

	"github.com/banai-ci/banai/infra"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/plumbing/transport/ssh"
)

var banai *infra.Banai

//GitBanaiOptions Auth to connect with git
type GitBanaiOptions struct {
	SecretID             string `json:"secretId,omitempty"`
	User                 string `json:"user,omitempty"`
	Password             string `json:"password,omitempty"`
	PrivateKeyPath       string `json:"privateKeyPath,omitempty"`
	RemoteRepositoryName string `json:"remoteRepositoryName,omitempty"`
}

func createAuthTransportFromUserPassword(user, password string) (ret transport.AuthMethod) {
	ret = &http.BasicAuth{
		Username: user, // yes, this can be anything except an empty string
		Password: password,
	}
	return
}

func createAuthTransportFromSSH(privateKeyFile, passphrase string) (ret transport.AuthMethod, err error) {

	_, err = os.Stat(privateKeyFile)
	if err != nil {
		return
	}

	ret, err = ssh.NewPublicKeysFromFile("git", privateKeyFile, passphrase)

	return
}

func createAuthTransportFromBanaiSecretID(secretID string) (ret transport.AuthMethod, err error) {
	if strings.TrimSpace(secretID) != "" {
		secretID = strings.TrimSpace(secretID)
		si, err := banai.GetSecret(secretID)
		banai.PanicOnError(err)
		switch si.GetType() {
		case infra.SecretTypeUserPass:
			up := si.(infra.UserPassword)
			err = nil
			ret = createAuthTransportFromUserPassword(up.User, up.Password)
		case infra.SecretTypeSSH:
			sshInfo := si.(infra.SSHWithPrivate)
			ret, err = createAuthTransportFromSSH(sshInfo.PrivateKeyFile, sshInfo.Passphrase)
		} //switch
	}
	err = fmt.Errorf("Secret Not Found")
	return
}

func createAuthFromGitOptions(cloneOptions GitBanaiOptions) (creds transport.AuthMethod, err error) {

	if strings.TrimSpace(cloneOptions.SecretID) != "" {
		creds, err = createAuthTransportFromBanaiSecretID(cloneOptions.SecretID)
	} else if cloneOptions.User != "" {
		err = nil
		creds = createAuthTransportFromUserPassword(cloneOptions.User, cloneOptions.Password)
	} else if cloneOptions.PrivateKeyPath != "" {
		creds, err = createAuthTransportFromSSH(cloneOptions.PrivateKeyPath, cloneOptions.Password)
	}
	return
}

func gitClone(originURL string, targetFolder string, opt ...GitBanaiOptions) {
	targetFolder = strings.TrimSpace(targetFolder)
	if targetFolder == "" {
		targetFolder = "."
	}
	var gitBanaiOpt *GitBanaiOptions
	if opt != nil && len(opt) > 0 {
		gitBanaiOpt = &opt[0]
	}
	var err error
	var creds transport.AuthMethod
	if gitBanaiOpt != nil {
		creds, err = createAuthFromGitOptions(*gitBanaiOpt)
		banai.PanicOnError(err)
	}

	_, err = git.PlainClone(targetFolder, false, &git.CloneOptions{
		Auth: creds,
		URL:  originURL,
	})

	banai.PanicOnError(err)

}

func gitPull(localRepoFolder string, opt ...GitBanaiOptions) {
	if strings.TrimSpace(localRepoFolder) == "" {
		localRepoFolder = "."
	}

	var banaiGitOpt *GitBanaiOptions
	if opt != nil && len(opt) > 0 {
		banaiGitOpt = &opt[0]
	}

	var err error
	var creds transport.AuthMethod
	if banaiGitOpt != nil {
		creds, err = createAuthFromGitOptions(*banaiGitOpt)
		banai.PanicOnError(err)
	}

	r, err := git.PlainOpen(localRepoFolder)
	banai.PanicOnError(err)
	w, err := r.Worktree()
	banai.PanicOnError(err)

	pullOpt := &git.PullOptions{
		Auth: creds,
	}
	if banaiGitOpt != nil {
		if banaiGitOpt.RemoteRepositoryName != "" {
			pullOpt.RemoteName = banaiGitOpt.RemoteRepositoryName
		}
	}

	err = w.Pull(pullOpt)
	banai.PanicOnError(err)
}

func gitPush(localRepoFolder string, force bool, opt ...GitBanaiOptions) {
	if strings.TrimSpace(localRepoFolder) == "" {
		localRepoFolder = "."
	}

	var banaiGitOpt *GitBanaiOptions
	if opt != nil && len(opt) > 0 {
		banaiGitOpt = &opt[0]
	}

	var err error
	var creds transport.AuthMethod
	if banaiGitOpt != nil {
		creds, err = createAuthFromGitOptions(*banaiGitOpt)
		banai.PanicOnError(err)
	}

	r, err := git.PlainOpen(localRepoFolder)
	banai.PanicOnError(err)
	pushOpt := &git.PushOptions{
		Auth:  creds,
		Force: force,
	}
	if banaiGitOpt != nil {
		if banaiGitOpt.RemoteRepositoryName != "" {
			pushOpt.RemoteName = banaiGitOpt.RemoteRepositoryName
		}
	}

	err = r.Push(pushOpt)

	if err != nil { //ignore error if git is up to date with remote
		if err == git.NoErrAlreadyUpToDate {
			err = nil
		}
	}

	banai.PanicOnError(err)
}

//RegisterJSObjects register git objects
func RegisterJSObjects(b *infra.Banai) {
	banai = b

	banai.Jse.GlobalObject().Set("gitClone", gitClone)
	banai.Jse.GlobalObject().Set("gitPull", gitPull)
	banai.Jse.GlobalObject().Set("gitPush", gitPush)
}
