package gitclient

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/banai-ci/banai/infra"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/plumbing/transport/ssh"
)

var banai *infra.Banai

//BanaiGitOptions Auth to connect with git
type BanaiGitOptions struct {
	SecretID             string `json:"secretId,omitempty"`
	User                 string `json:"user,omitempty"`
	Password             string `json:"password,omitempty"`
	PrivateKeyPath       string `json:"privateKeyPath,omitempty"`
	RemoteRepositoryName string `json:"remoteRepositoryName,omitempty"`
}

//BanaiGitReferenceInfo Overview of a git tag
type BanaiGitReferenceInfo struct {
	Hash     string `json:"hash,omitempty"`
	Name     string `json:"name,omitempty"`
	LongName string `json:"longName,omitempty"`
	IsRemote bool   `json:"isRemote,omitempty"`
	IsTag    bool   `json:"isTag,omitempty"`
	IsBranch bool   `json:"isBranch,omitempty"`
}

func createBanaiGitReferenceFromGitReference(rev *plumbing.Reference, isRemote bool) BanaiGitReferenceInfo {
	if rev == nil {
		return BanaiGitReferenceInfo{}
	}

	return BanaiGitReferenceInfo{
		Hash:     rev.Hash().String(),
		Name:     rev.Name().Short(),
		LongName: rev.Name().String(),
		IsRemote: isRemote,
		IsTag:    rev.Name().IsTag(),
		IsBranch: rev.Name().IsBranch(),
	}

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

func createAuthFromGitOptions(cloneOptions BanaiGitOptions) (creds transport.AuthMethod, err error) {

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

func gitClone(originURL string, targetFolder string, opt ...BanaiGitOptions) {
	targetFolder = strings.TrimSpace(targetFolder)
	if targetFolder == "" {
		targetFolder = "."
	}
	var gitBanaiOpt *BanaiGitOptions
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

func openLocalGitRepository(localRepoFolder string, opt ...BanaiGitOptions) (repo *git.Repository, banaiGitOpt *BanaiGitOptions, auth transport.AuthMethod, err error) {

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

	} else {
		banaiGitOpt = &BanaiGitOptions{}
	}

	if banaiGitOpt.RemoteRepositoryName == "" {
		banaiGitOpt.RemoteRepositoryName = git.DefaultRemoteName
	}

	repo, err = git.PlainOpen(localRepoFolder)

	banai.PanicOnError(err)

	err = repo.Fetch(&git.FetchOptions{
		RemoteName: banaiGitOpt.RemoteRepositoryName,
		Auth:       auth,
	})

	if err == git.NoErrAlreadyUpToDate {
		err = nil
	}

	return
}

func openGitRemoteRepository(localRepo *git.Repository, banaiOpt *BanaiGitOptions) (*git.Remote, error) {
	//---------- list remote branches
	var remoteRepo *git.Remote
	var err error

	repoOpt := BanaiGitOptions{
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

func gitPull(localRepoFolder string, opt ...BanaiGitOptions) {

	repo, banaiOpt, creds, err := openLocalGitRepository(localRepoFolder, opt...)
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

func gitPush(localRepoFolder string, force bool, opt ...BanaiGitOptions) {
	repo, banaiOpt, creds, err := openLocalGitRepository(localRepoFolder, opt...)
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

func meshLocalAndRemoteReference(localReferences []BanaiGitReferenceInfo, remoteReferences []BanaiGitReferenceInfo) []BanaiGitReferenceInfo {
	known := make(map[string]string)
	ret := make([]BanaiGitReferenceInfo, 0, len(remoteReferences))

	for _, local := range localReferences {
		known[local.Name] = local.Hash
		ret = append(ret, local)
	}

	for _, remote := range remoteReferences {
		if _, ok := known[remote.Name]; !ok {
			known[remote.Name] = remote.Hash
			ret = append(ret, remote)
		}
	}
	return ret
}

func gitBranches(localRepoFolder string, opt ...BanaiGitOptions) []BanaiGitReferenceInfo {
	repo, repoOpt, auth, err := openLocalGitRepository(localRepoFolder, opt...)
	banai.PanicOnError(err)
	branchRefs, err := repo.Branches()
	banai.PanicOnError(err)
	defer branchRefs.Close()

	//-------- list local Branches
	localBranches := make([]BanaiGitReferenceInfo, 0)
	branchRefs.ForEach(func(rev *plumbing.Reference) error {
		localBranches = append(localBranches, createBanaiGitReferenceFromGitReference(rev, false))
		return nil
	})

	remoteRepo, err := openGitRemoteRepository(repo, repoOpt)
	banai.PanicOnError(err)

	var remoteItems []*plumbing.Reference
	remoteItems, err = remoteRepo.List(&git.ListOptions{
		Auth: auth,
	})

	remoteBranches := make([]BanaiGitReferenceInfo, 0)
	for _, ref := range remoteItems {
		if ref.Name().IsBranch() {
			remoteBranches = append(remoteBranches, createBanaiGitReferenceFromGitReference(ref, true))
		}
	}

	return meshLocalAndRemoteReference(localBranches, remoteBranches)
}

func gitTags(localRepoFolder string, opt ...BanaiGitOptions) []BanaiGitReferenceInfo {
	repo, banaiOpt, creds, err := openLocalGitRepository(localRepoFolder, opt...)
	banai.PanicOnError(err)
	tagrefs, err := repo.Tags()
	banai.PanicOnError(err)
	defer tagrefs.Close()
	localReferences := make([]BanaiGitReferenceInfo, 0)
	tagrefs.ForEach(func(rev *plumbing.Reference) error {
		localReferences = append(localReferences, createBanaiGitReferenceFromGitReference(rev, false))
		return nil
	})

	remoteRepo, err := openGitRemoteRepository(repo, banaiOpt)
	banai.PanicOnError(err)

	var remoteItems []*plumbing.Reference
	remoteItems, err = remoteRepo.List(&git.ListOptions{
		Auth: creds,
	})

	remoteReferences := make([]BanaiGitReferenceInfo, 0)
	for _, ref := range remoteItems {
		if ref.Name().IsTag() {
			remoteReferences = append(remoteReferences, createBanaiGitReferenceFromGitReference(ref, true))
		}
	}

	return meshLocalAndRemoteReference(localReferences, remoteReferences)
}

func gitCheckout(localRepoFolder, revisionID string, opt ...BanaiGitOptions) BanaiGitReferenceInfo {
	repo, repoOpt, auth, err := openLocalGitRepository(localRepoFolder, opt...)
	banai.PanicOnError(err)

	w, err := repo.Worktree()
	banai.PanicOnError(err)
	var found = false
	hash, err := repo.ResolveRevision(plumbing.Revision(revisionID))
	if err == nil {
		err = w.Checkout(&git.CheckoutOptions{
			Hash: *hash,
		})
	} else {
		branches, err := repo.Branches()
		banai.PanicOnError(err)
		var branchHash plumbing.Hash
		found = false

		branches.ForEach(func(ref *plumbing.Reference) error {
			if ref.Name().String() == revisionID || ref.Name().Short() == revisionID {
				branchHash = ref.Hash()
				found = true
			}
			return nil
		})

		if found {
			err = w.Checkout(&git.CheckoutOptions{
				Hash: branchHash,
			})
			banai.PanicOnError(err)
		} else {
			var tagHash plumbing.Hash
			found = false
			tags, err := repo.Tags()
			banai.PanicOnError(err)
			defer tags.Close()
			tags.ForEach(func(ref *plumbing.Reference) error {
				if ref.Name().String() == revisionID || ref.Name().Short() == revisionID {
					tagHash = ref.Hash()
					found = true
				}

				return nil
			})

			if found {
				err = w.Checkout(&git.CheckoutOptions{
					Hash: tagHash,
				})
				banai.PanicOnError(err)
			}
		}

	}

	if !found {
		remote, err := openGitRemoteRepository(repo, repoOpt)
		banai.PanicOnError(err)
		remote.Fetch(&git.FetchOptions{
			RemoteName: repoOpt.RemoteRepositoryName,
			Auth:       auth,
		})

		remoteReferences, err := remote.List(&git.ListOptions{
			Auth: auth,
		})
		banai.PanicOnError(err)

		for _, ref := range remoteReferences {
			if revisionID == ref.Name().String() || revisionID == ref.Name().Short() {

				err = w.Checkout(&git.CheckoutOptions{
					Hash: ref.Hash(),
				})
				banai.PanicOnError(err)
				found = true
				break
			}
		}

		if !found {
			banai.PanicOnError(fmt.Errorf("Invalid referenc, should be branch, tag or commit"))
		}

	}

	ref, err := repo.Head()
	banai.PanicOnError(err)

	return createBanaiGitReferenceFromGitReference(ref, false)
}

func gitCommit(localRepoFolder string, commitMessage string, opt ...BanaiGitOptions) BanaiGitReferenceInfo {
	repo, _, _, err := openLocalGitRepository(localRepoFolder, opt...)
	banai.PanicOnError(err)
	w, err := repo.Worktree()
	banai.PanicOnError(err)
	commit, err := w.Commit(commitMessage, &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Banai CI",
			Email: "Banai@Banai",
			When:  time.Now(),
		},
	})
	banai.PanicOnError(err)

	commitObj, err := repo.CommitObject(commit)
	banai.PanicOnError(err)

	return BanaiGitReferenceInfo{
		Hash: commitObj.Hash.String(),
	}

}

func gitSwitchBranch(localRepoFolder string, newBranchName string, opt ...BanaiGitOptions) BanaiGitReferenceInfo {
	repo, _, _, err := openLocalGitRepository(localRepoFolder, opt...)
	banai.PanicOnError(err)
	banai.PanicOnError(err)

	w, err := repo.Worktree()
	banai.PanicOnError(err)

	//first try to checkout the branch
	if !strings.HasPrefix(newBranchName, "refs/heads") {
		newBranchName = "refs/heads/" + newBranchName
	}
	err = w.Checkout(&git.CheckoutOptions{
		Branch: plumbing.ReferenceName(newBranchName),
		Create: false,
	})
	if err != nil {
		err = w.Checkout(&git.CheckoutOptions{
			Branch: plumbing.ReferenceName(newBranchName),
			Create: true,
		})
		banai.PanicOnError(err)
	}

	newBranchRef, err := repo.Head()
	banai.PanicOnError(err)
	return createBanaiGitReferenceFromGitReference(newBranchRef, false)
}

//RegisterJSObjects register git objects
func RegisterJSObjects(b *infra.Banai) {
	banai = b

	banai.Jse.GlobalObject().Set("gitClone", gitClone)
	banai.Jse.GlobalObject().Set("gitPull", gitPull)
	banai.Jse.GlobalObject().Set("gitPush", gitPush)
	banai.Jse.GlobalObject().Set("gitBranches", gitBranches)
	banai.Jse.GlobalObject().Set("gitTags", gitTags)
	banai.Jse.GlobalObject().Set("gitCheckout", gitCheckout)
	banai.Jse.GlobalObject().Set("gitCommit", gitCommit)
	banai.Jse.GlobalObject().Set("gitSwitchBranch", gitSwitchBranch)

}
