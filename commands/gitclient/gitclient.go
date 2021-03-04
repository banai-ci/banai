package gitclient

import (
	"fmt"
	"os"
	"strings"

	"github.com/banai-ci/banai/infra"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
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

//BanaiGitRevisionInfo Overview of a git tag
type BanaiGitRevisionInfo struct {
	Hash     string `json:"hash,omitempty"`
	Name     string `json:"name,omitempty"`
	LongName string `json:"longName,omitempty"`
	IsRemote bool   `json:"isRemote,omitempty"`
	IsTag    bool   `json:"isTag,omitempty"`
	IsBranch bool   `json:"isBranch,omitempty"`
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
		var si infra.SecretInfo
		si, err = banai.GetSecret(secretID)
		banai.PanicOnError(err)
		switch si.GetType() {
		case infra.SecretTypeUserPass:
			up := si.(infra.UserPassword)
			err = nil
			ret = createAuthTransportFromUserPassword(up.User, up.Password)
			return
		case infra.SecretTypeSSH:
			sshInfo := si.(infra.SSHWithPrivate)
			ret, err = createAuthTransportFromSSH(sshInfo.PrivateKeyFile, sshInfo.Passphrase)
			return
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

	var r *git.Repository
	r, err = git.PlainClone(targetFolder, false, &git.CloneOptions{
		Auth: creds,
		URL:  originURL,
	})
	banai.PanicOnError(err)

	err = r.Fetch(&git.FetchOptions{
		Auth: creds,
	})

	return
}

func openGitRepositoryOnLocal(localRepoFolder string, opt ...GitBanaiOptions) (repo *git.Repository, banaiGitOpt *GitBanaiOptions, auth transport.AuthMethod, err error) {

	if strings.TrimSpace(localRepoFolder) == "" {
		localRepoFolder = "."
	}

	if opt != nil && len(opt) > 0 {
		banaiGitOpt = &opt[0]
	}
	if banaiGitOpt != nil {
		auth, err = createAuthFromGitOptions(*banaiGitOpt)
		if err != nil {
			return
		}
	}
	repo, err = git.PlainOpen(localRepoFolder)

	banai.PanicOnError(err)

	err = repo.Fetch(&git.FetchOptions{
		Auth: auth,
	})

	if err == git.NoErrAlreadyUpToDate {
		err = nil
	}

	return
}

func openGitRemoteRepository(localRepo *git.Repository, banaiOpt *GitBanaiOptions) (*git.Remote, error) {
	//---------- list remote branches
	var remoteRepo *git.Remote
	var err error

	repoOpt := GitBanaiOptions{
		RemoteRepositoryName: git.DefaultRemoteName,
	}

	if banaiOpt != nil {
		repoOpt = *banaiOpt
	}

	if repoOpt.RemoteRepositoryName != "" {
		remoteRepo, err = localRepo.Remote(repoOpt.RemoteRepositoryName)
	} else {
		remoteRepo, err = localRepo.Remote(git.DefaultRemoteName)
	}

	return remoteRepo, err
}

func gitPull(localRepoFolder string, opt ...GitBanaiOptions) {

	repo, banaiOpt, creds, err := openGitRepositoryOnLocal(localRepoFolder, opt...)
	banai.PanicOnError(err)
	w, err := repo.Worktree()
	banai.PanicOnError(err)

	pullOpt := &git.PullOptions{
		Auth: creds,
	}

	if banaiOpt != nil {
		if banaiOpt.RemoteRepositoryName != "" {
			pullOpt.RemoteName = banaiOpt.RemoteRepositoryName
		} else {
			pullOpt.RemoteName = git.DefaultRemoteName
		}
	}

	err = w.Pull(pullOpt)
	if err == git.NoErrAlreadyUpToDate {
		err = nil
	}
	banai.PanicOnError(err)
}

func gitPush(localRepoFolder string, force bool, opt ...GitBanaiOptions) {
	repo, banaiOpt, creds, err := openGitRepositoryOnLocal(localRepoFolder, opt...)
	banai.PanicOnError(err)
	pushOpt := &git.PushOptions{
		Auth:  creds,
		Force: force,
	}
	if banaiOpt != nil {
		if banaiOpt.RemoteRepositoryName != "" {
			pushOpt.RemoteName = banaiOpt.RemoteRepositoryName
		} else {
			pushOpt.RemoteName = git.DefaultRemoteName
		}
	}

	err = repo.Push(pushOpt)

	if err != nil { //ignore error if git is up to date with remote
		if err == git.NoErrAlreadyUpToDate {
			err = nil
		}
	}

	banai.PanicOnError(err)
}

func meshLocalAndRemote(localRevisions []BanaiGitRevisionInfo, remoteRevisions []BanaiGitRevisionInfo) []BanaiGitRevisionInfo {
	known := make(map[string]string)
	ret := make([]BanaiGitRevisionInfo, 0, len(remoteRevisions))

	for _, local := range localRevisions {
		known[local.Name] = local.Hash
		ret = append(ret, local)
	}

	for _, remote := range remoteRevisions {
		if _, ok := known[remote.Name]; !ok {
			known[remote.Name] = remote.Hash
			ret = append(ret, remote)
		}
	}
	return ret
}

func gitBranches(localRepoFolder string, opt ...GitBanaiOptions) []BanaiGitRevisionInfo {
	repo, repoOpt, auth, err := openGitRepositoryOnLocal(localRepoFolder, opt...)
	banai.PanicOnError(err)
	branchRefs, err := repo.Branches()

	//-------- list local Branches
	localBranches := make([]BanaiGitRevisionInfo, 0)
	branchRefs.ForEach(func(rev *plumbing.Reference) error {
		localBranches = append(localBranches, BanaiGitRevisionInfo{
			Hash:     rev.Hash().String(),
			Name:     rev.Name().Short(),
			LongName: rev.Name().String(),
			IsBranch: rev.Name().IsBranch(),
			IsTag:    rev.Name().IsTag(),
		})
		return nil
	})

	remoteRepo, err := openGitRemoteRepository(repo, repoOpt)
	banai.PanicOnError(err)

	var remoteItems []*plumbing.Reference
	remoteItems, err = remoteRepo.List(&git.ListOptions{
		Auth: auth,
	})

	remoteBranches := make([]BanaiGitRevisionInfo, 0)
	for _, rev := range remoteItems {
		if rev.Name().IsBranch() {
			remoteBranches = append(remoteBranches, BanaiGitRevisionInfo{
				Hash:     rev.Hash().String(),
				Name:     rev.Name().Short(),
				LongName: rev.Name().String(),
				IsBranch: rev.Name().IsBranch(),
				IsTag:    rev.Name().IsTag(),
				IsRemote: true,
			})
		}
	}

	return meshLocalAndRemote(localBranches, remoteBranches)
}

func gitTags(localRepoFolder string, opt ...GitBanaiOptions) []BanaiGitRevisionInfo {
	repo, banaiOpt, creds, err := openGitRepositoryOnLocal(localRepoFolder, opt...)
	banai.PanicOnError(err)
	tagrefs, err := repo.Tags()

	localRevisions := make([]BanaiGitRevisionInfo, 0)
	tagrefs.ForEach(func(rev *plumbing.Reference) error {
		localRevisions = append(localRevisions, BanaiGitRevisionInfo{
			Hash:     rev.Hash().String(),
			Name:     rev.Name().Short(),
			LongName: rev.Name().String(),
			IsBranch: rev.Name().IsBranch(),
			IsTag:    rev.Name().IsTag(),
		})

		return nil
	})

	remoteRepo, err := openGitRemoteRepository(repo, banaiOpt)
	banai.PanicOnError(err)

	var remoteItems []*plumbing.Reference
	remoteItems, err = remoteRepo.List(&git.ListOptions{
		Auth: creds,
	})

	remoteRevisions := make([]BanaiGitRevisionInfo, 0)
	for _, rev := range remoteItems {
		if rev.Name().IsTag() {
			remoteRevisions = append(remoteRevisions, BanaiGitRevisionInfo{
				Hash:     rev.Hash().String(),
				Name:     rev.Name().Short(),
				LongName: rev.Name().String(),
				IsBranch: rev.Name().IsBranch(),
				IsTag:    rev.Name().IsTag(),
				IsRemote: true,
			})
		}
	}

	return meshLocalAndRemote(localRevisions, remoteRevisions)
}

//RegisterJSObjects register git objects
func RegisterJSObjects(b *infra.Banai) {
	banai = b

	banai.Jse.GlobalObject().Set("gitClone", gitClone)
	banai.Jse.GlobalObject().Set("gitPull", gitPull)
	banai.Jse.GlobalObject().Set("gitPush", gitPush)
	banai.Jse.GlobalObject().Set("gitBranches", gitBranches)
	banai.Jse.GlobalObject().Set("gitTags", gitTags)

}
