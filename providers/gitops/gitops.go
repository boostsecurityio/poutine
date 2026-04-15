package gitops

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/boostsecurityio/poutine/models"
	gogit "github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/config"
	"github.com/go-git/go-git/v6/plumbing"
	"github.com/go-git/go-git/v6/plumbing/object"
	"github.com/go-git/go-git/v6/plumbing/protocol/packp"
	"github.com/go-git/go-git/v6/plumbing/storer"
	"github.com/go-git/go-git/v6/plumbing/transport"
	gogithttp "github.com/go-git/go-git/v6/plumbing/transport/http"
	"github.com/go-git/go-git/v6/storage/memory"
	"github.com/rs/zerolog/log"
)

func init() {
	// Override go-git's default HTTP transport with higher connection limits
	// to support concurrent cloning of many repos from the same host.
	httpTransport := gogithttp.NewTransport(&gogithttp.TransportOptions{
		Client: &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxConnsPerHost:     20,
				MaxIdleConnsPerHost: 20,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	})
	transport.Register("http", httpTransport)
	transport.Register("https", httpTransport)
}

var ErrRepoNotReachable = errors.New("repo or ref not reachable")
var ErrRemoteRefNotFound = errors.New("remote ref not found")

type resolvedRefKind int

const (
	resolvedRefHead resolvedRefKind = iota
	resolvedRefBranch
	resolvedRefTag
	resolvedRefCommit
)

type resolvedRef struct {
	kind       resolvedRefKind
	input      string
	fullRef    string
	localRef   plumbing.ReferenceName
	commitHash plumbing.Hash
}

// inMemRepo holds an in-memory git repository.
type inMemRepo struct {
	store         *memory.Storage
	repo          *gogit.Repository
	headRef       plumbing.Hash
	token         string
	url           string
	defaultBranch string
}

// GitClient implements git operations using go-git with in-memory storage.
type GitClient struct {
	mu    sync.RWMutex
	repos map[string]*inMemRepo
}

// GitCommand is kept for API compatibility but is unused by the go-git implementation.
type GitCommand interface{}

func NewGitClient(_ *GitCommand) *GitClient {
	return &GitClient{repos: make(map[string]*inMemRepo)}
}

func authForToken(token string) transport.AuthMethod {
	if token == "" {
		return nil
	}
	return &gogithttp.BasicAuth{
		Username: "x-access-token",
		Password: token,
	}
}

func (g *GitClient) getRepo(key string) (*inMemRepo, error) {
	g.mu.RLock()
	r, ok := g.repos[key]
	g.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("no in-memory repo found for key %s", key)
	}
	return r, nil
}

func (g *GitClient) Clone(ctx context.Context, clonePath string, url string, token string, ref string) error {
	store := memory.NewStorage()
	repo, err := gogit.Init(store, nil)
	if err != nil {
		return fmt.Errorf("failed to init in-memory repo: %w", err)
	}

	_, err = repo.CreateRemote(&config.RemoteConfig{
		Name: "origin",
		URLs: []string{url},
	})
	if err != nil {
		return fmt.Errorf("failed to add origin remote: %w", err)
	}

	// Build refspec and fetch. For HEAD, try common defaults first to avoid
	// an extra ls-remote round-trip.
	var defaultBranch string
	resolved := &resolvedRef{
		kind:  resolvedRefHead,
		input: ref,
	}
	fetchOpts := &gogit.FetchOptions{
		RemoteName: "origin",
		Depth:      1,
		Filter:     packp.FilterBlobNone(),
		Tags:       gogit.NoTags,
		Auth:       authForToken(token),
	}

	switch {
	case ref == "HEAD":
		// Try "main" first (most common), then "master", then ls-remote as fallback
		for _, branch := range []string{"main", "master"} {
			fetchOpts.RefSpecs = []config.RefSpec{
				config.RefSpec(fmt.Sprintf("+refs/heads/%s:refs/remotes/origin/%s", branch, branch)),
			}
			err = repo.FetchContext(ctx, fetchOpts)
			if err == nil {
				defaultBranch = branch
				resolved.localRef = plumbing.ReferenceName("refs/remotes/origin/" + branch)
				break
			}
			if classifyFetchError(err) != nil && !strings.Contains(err.Error(), "couldn't find remote ref") {
				return classifyFetchError(err)
			}
		}
		if defaultBranch == "" {
			// Neither main nor master — ls-remote to find actual default
			discovered := discoverDefaultBranchFromURL(url, token)
			if discovered != "" {
				fetchOpts.RefSpecs = []config.RefSpec{
					config.RefSpec(fmt.Sprintf("+refs/heads/%s:refs/remotes/origin/%s", discovered, discovered)),
				}
				resolved.localRef = plumbing.ReferenceName("refs/remotes/origin/" + discovered)
			} else {
				fetchOpts.RefSpecs = []config.RefSpec{config.RefSpec("+refs/heads/*:refs/remotes/origin/*")}
			}
			err = repo.FetchContext(ctx, fetchOpts)
			if err := classifyFetchError(err); err != nil {
				return err
			}
			defaultBranch = discovered
		}
	default:
		resolved, err = resolveRemoteRef(repo, url, token, ref)
		if err != nil {
			return err
		}
		if resolved.kind == resolvedRefBranch {
			defaultBranch = strings.TrimPrefix(resolved.fullRef, "refs/heads/")
		}
		if err := fetchResolvedRef(ctx, repo, fetchOpts, resolved); err != nil {
			return err
		}
	}

	headHash, err := resolveFetchedTargetToCommit(store, repo, resolved, token)
	if err != nil {
		return fmt.Errorf("failed to resolve head after clone: %w", err)
	}

	// Phase 2: Walk entire tree to find all YAML blobs, then fetch only those
	commit, err := object.GetCommit(store, headHash)
	if err != nil {
		return fmt.Errorf("failed to get commit: %w", err)
	}
	tree, err := commit.Tree()
	if err != nil {
		return fmt.Errorf("failed to get tree: %w", err)
	}

	var blobHashes []plumbing.Hash
	collectYAMLBlobHashes(store, tree, "", &blobHashes)

	if len(blobHashes) > 0 {
		if err := fetchSpecificBlobs(ctx, store, url, token, blobHashes); err != nil {
			return fmt.Errorf("failed to fetch YAML blobs: %w", err)
		}
	}

	g.mu.Lock()
	g.repos[clonePath] = &inMemRepo{
		store:         store,
		repo:          repo,
		headRef:       headHash,
		token:         token,
		url:           url,
		defaultBranch: defaultBranch,
	}
	g.mu.Unlock()

	return nil
}

func fetchResolvedRef(ctx context.Context, repo *gogit.Repository, fetchOpts *gogit.FetchOptions, resolved *resolvedRef) error {
	switch resolved.kind {
	case resolvedRefBranch, resolvedRefTag:
		fetchOpts.RefSpecs = []config.RefSpec{
			config.RefSpec(fmt.Sprintf("+%s:%s", resolved.fullRef, resolved.localRef)),
		}
	case resolvedRefCommit:
		fetchOpts.RefSpecs = []config.RefSpec{
			config.RefSpec(fmt.Sprintf("+%s:%s", resolved.commitHash.String(), resolved.localRef)),
		}
	default:
		return fmt.Errorf("unsupported resolved ref kind for fetch: %q", resolved.input)
	}

	err := repo.FetchContext(ctx, fetchOpts)
	if err := classifyFetchError(err); err != nil {
		return err
	}
	return nil
}

func (g *GitClient) FetchCone(ctx context.Context, clonePath, url, token, ref string, cone string) error {
	store := memory.NewStorage()
	repo, err := gogit.Init(store, nil)
	if err != nil {
		return fmt.Errorf("failed to init in-memory repo: %w", err)
	}

	_, err = repo.CreateRemote(&config.RemoteConfig{
		Name: "origin",
		URLs: []string{url},
	})
	if err != nil {
		return fmt.Errorf("failed to add origin remote: %w", err)
	}

	// FetchCone is called with refspecs like "refs/heads/*:refs/remotes/origin/*"
	// The cone parameter is unused with in-memory git (no sparse-checkout equivalent)
	refSpecs := []config.RefSpec{
		config.RefSpec("+" + ref),
	}

	err = repo.FetchContext(ctx, &gogit.FetchOptions{
		RemoteName: "origin",
		Depth:      1,
		Filter:     packp.FilterBlobNone(),
		Tags:       gogit.NoTags,
		RefSpecs:   refSpecs,
		Auth:       authForToken(token),
	})
	if err := classifyFetchError(err); err != nil {
		return fmt.Errorf("failed to fetch cone: %w", err)
	}

	// FetchCone fetches all branches with blob:none — only trees.
	// BlobMatches will fetch individual blobs on demand via fetchSpecificBlobs.
	g.mu.Lock()
	g.repos[clonePath] = &inMemRepo{
		store: store,
		repo:  repo,
		token: token,
		url:   url,
	}
	g.mu.Unlock()

	return nil
}

func (g *GitClient) CommitSHA(clonePath string) (string, error) {
	r, err := g.getRepo(clonePath)
	if err != nil {
		return "", err
	}
	return r.headRef.String(), nil
}

func (g *GitClient) LastCommitDate(ctx context.Context, clonePath string) (time.Time, error) {
	r, err := g.getRepo(clonePath)
	if err != nil {
		return time.Time{}, err
	}
	commit, err := object.GetCommit(r.store, r.headRef)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to get commit: %w", err)
	}
	return commit.Committer.When, nil
}

func (g *GitClient) GetRemoteOriginURL(ctx context.Context, repoPath string) (string, error) {
	r, err := g.getRepo(repoPath)
	if err != nil {
		return "", err
	}
	remote, err := r.repo.Remote("origin")
	if err != nil {
		return "", fmt.Errorf("failed to get origin remote: %w", err)
	}
	urls := remote.Config().URLs
	if len(urls) == 0 {
		return "", errors.New("origin remote has no URLs")
	}
	return urls[0], nil
}

func (g *GitClient) GetRepoHeadBranchName(ctx context.Context, repoPath string) (string, error) {
	r, err := g.getRepo(repoPath)
	if err != nil {
		return "", err
	}

	// Return stored default branch from Clone() — no network call needed
	if r.defaultBranch != "" {
		return r.defaultBranch, nil
	}

	return g.findBranchFromRefs(r)
}

func (g *GitClient) findBranchFromRefs(r *inMemRepo) (string, error) {
	refs, err := r.repo.References()
	if err != nil {
		return "HEAD", nil
	}

	var branchName string
	err = refs.ForEach(func(ref *plumbing.Reference) error {
		name := string(ref.Name())
		if strings.HasPrefix(name, "refs/remotes/origin/") && !strings.HasSuffix(name, "/HEAD") {
			if ref.Hash() == r.headRef {
				branchName = strings.TrimPrefix(name, "refs/remotes/origin/")
				return errors.New("found") // break iteration
			}
		}
		return nil
	})
	if branchName != "" {
		return branchName, nil
	}
	_ = err
	return "HEAD", nil
}

func (g *GitClient) GetUniqWorkflowsBranches(ctx context.Context, clonePath string) (map[string][]models.BranchInfo, error) {
	r, err := g.getRepo(clonePath)
	if err != nil {
		return nil, err
	}

	// Group remote refs by commit hash (dedup branches pointing to same commit)
	branchesMap := make(map[plumbing.Hash][]string)
	refs, err := r.repo.References()
	if err != nil {
		return nil, fmt.Errorf("failed to list references: %w", err)
	}
	err = refs.ForEach(func(ref *plumbing.Reference) error {
		name := string(ref.Name())
		if strings.HasPrefix(name, "refs/remotes/origin/") && !strings.HasSuffix(name, "/HEAD") {
			branch := strings.TrimPrefix(name, "refs/remotes/origin/")
			branchesMap[ref.Hash()] = append(branchesMap[ref.Hash()], branch)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to iterate references: %w", err)
	}

	workflowsInfo := make(map[string][]models.BranchInfo)
	for commitHash, branches := range branchesMap {
		if len(branches) == 0 {
			continue
		}

		workflows, err := g.getBranchWorkflows(r, commitHash)
		if err != nil {
			log.Debug().Err(err).Str("branch", branches[0]).Msg("failed to get workflows for branch")
			continue
		}

		for blobSHA, paths := range workflows {
			var infos []models.BranchInfo
			for _, branch := range branches {
				infos = append(infos, models.BranchInfo{
					BranchName: branch,
					FilePath:   paths,
				})
			}
			workflowsInfo[blobSHA] = append(workflowsInfo[blobSHA], infos...)
		}
	}

	return workflowsInfo, nil
}

func (g *GitClient) getBranchWorkflows(r *inMemRepo, commitHash plumbing.Hash) (map[string][]string, error) {
	commit, err := object.GetCommit(r.store, commitHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get commit: %w", err)
	}

	tree, err := commit.Tree()
	if err != nil {
		return nil, fmt.Errorf("failed to get tree: %w", err)
	}

	workflowTree, err := tree.Tree(".github/workflows")
	if err != nil {
		return nil, nil // no workflows directory
	}

	// Use tree.Entries instead of tree.Files() — works with blobless clones
	// since we only need blob hashes, not content
	records := make(map[string][]string)
	for _, entry := range workflowTree.Entries {
		if !entry.Mode.IsFile() {
			continue
		}
		name := entry.Name
		if strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml") {
			blobSHA := entry.Hash.String()
			filePath := ".github/workflows/" + name
			records[blobSHA] = append(records[blobSHA], filePath)
		}
	}

	return records, nil
}

func (g *GitClient) BlobMatches(ctx context.Context, clonePath, blobSha string, re *regexp.Regexp) (bool, []byte, error) {
	r, err := g.getRepo(clonePath)
	if err != nil {
		return false, nil, err
	}

	hash := plumbing.NewHash(blobSha)
	blob, err := object.GetBlob(r.store, hash)
	if err != nil {
		// Blob missing (blobless clone) — fetch it on demand
		if err := fetchSpecificBlobs(ctx, r.store, r.url, r.token, []plumbing.Hash{hash}); err != nil {
			return false, nil, fmt.Errorf("error fetching blob %s: %w", blobSha, err)
		}
		blob, err = object.GetBlob(r.store, hash)
		if err != nil {
			return false, nil, fmt.Errorf("error getting blob %s after fetch: %w", blobSha, err)
		}
	}

	reader, err := blob.Reader()
	if err != nil {
		return false, nil, fmt.Errorf("error reading blob %s: %w", blobSha, err)
	}
	defer reader.Close()

	content, err := io.ReadAll(reader)
	if err != nil {
		return false, nil, fmt.Errorf("error reading blob content %s: %w", blobSha, err)
	}

	return re.Match(content), content, nil
}

func (g *GitClient) ListFiles(clonePath string, extensions []string) (map[string][]byte, error) {
	r, err := g.getRepo(clonePath)
	if err != nil {
		return nil, err
	}

	commit, err := object.GetCommit(r.store, r.headRef)
	if err != nil {
		return nil, fmt.Errorf("failed to get commit: %w", err)
	}
	tree, err := commit.Tree()
	if err != nil {
		return nil, fmt.Errorf("failed to get tree: %w", err)
	}

	extSet := make(map[string]struct{}, len(extensions))
	for _, ext := range extensions {
		extSet[ext] = struct{}{}
	}

	files := make(map[string][]byte)
	collectFileContents(r.store, tree, "", extSet, files)
	return files, nil
}

// collectFileContents walks tree entries recursively and reads matching blob content.
func collectFileContents(store *memory.Storage, tree *object.Tree, prefix string, extSet map[string]struct{}, files map[string][]byte) {
	for _, entry := range tree.Entries {
		path := entry.Name
		if prefix != "" {
			path = prefix + "/" + entry.Name
		}

		if entry.Mode.IsFile() {
			matched := len(extSet) == 0
			if !matched {
				for ext := range extSet {
					if strings.HasSuffix(entry.Name, ext) {
						matched = true
						break
					}
				}
			}
			if !matched {
				continue
			}

			blob, err := object.GetBlob(store, entry.Hash)
			if err != nil {
				log.Debug().Err(err).Str("file", path).Msg("blob not available")
				continue
			}
			reader, err := blob.Reader()
			if err != nil {
				continue
			}
			content, err := io.ReadAll(reader)
			reader.Close()
			if err != nil {
				continue
			}
			files[path] = content
		} else {
			subTree, err := object.GetTree(store, entry.Hash)
			if err != nil {
				continue
			}
			collectFileContents(store, subTree, path, extSet, files)
		}
	}
}

// collectYAMLBlobHashes walks tree entries to find .yml/.yaml files and collects their blob hashes.
// This works with blobless clones since only tree objects are needed.
func collectYAMLBlobHashes(store *memory.Storage, tree *object.Tree, prefix string, hashes *[]plumbing.Hash) {
	for _, entry := range tree.Entries {
		path := entry.Name
		if prefix != "" {
			path = prefix + "/" + entry.Name
		}

		if entry.Mode.IsFile() {
			if strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml") {
				*hashes = append(*hashes, entry.Hash)
			}
		} else {
			subTree, err := object.GetTree(store, entry.Hash)
			if err != nil {
				continue
			}
			collectYAMLBlobHashes(store, subTree, path, hashes)
		}
	}
}

// fetchSpecificBlobs fetches specific blob objects by hash using the low-level
// git transport protocol. This allows us to do a blobless initial fetch (trees only)
// then surgically fetch only the blobs we actually need.
func fetchSpecificBlobs(ctx context.Context, store *memory.Storage, url string, token string, blobHashes []plumbing.Hash) error {
	ep, err := transport.NewEndpoint(url)
	if err != nil {
		return fmt.Errorf("failed to create endpoint: %w", err)
	}

	t, err := transport.Get(ep.Scheme)
	if err != nil {
		return fmt.Errorf("failed to get transport: %w", err)
	}

	sess, err := t.NewSession(store, ep, authForToken(token))
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	conn, err := sess.Handshake(ctx, transport.UploadPackService)
	if err != nil {
		return fmt.Errorf("failed to handshake: %w", err)
	}

	err = conn.Fetch(ctx, &transport.FetchRequest{
		Wants: blobHashes,
	})
	conn.Close()

	if err := classifyFetchError(err); err != nil {
		return err
	}
	return nil
}

func (g *GitClient) Cleanup(clonePath string) {
	g.mu.Lock()
	delete(g.repos, clonePath)
	g.mu.Unlock()
}

func resolveRemoteRef(repo *gogit.Repository, url string, token string, ref string) (*resolvedRef, error) {
	switch {
	case ref == "" || ref == "HEAD":
		return &resolvedRef{kind: resolvedRefHead, input: ref}, nil
	case looksLikeSHA(ref):
		return &resolvedRef{
			kind:       resolvedRefCommit,
			input:      ref,
			localRef:   plumbing.ReferenceName("refs/poutine/target"),
			commitHash: plumbing.NewHash(ref),
		}, nil
	case strings.HasPrefix(ref, "refs/heads/"):
		return &resolvedRef{
			kind:     resolvedRefBranch,
			input:    ref,
			fullRef:  ref,
			localRef: plumbing.ReferenceName("refs/remotes/origin/" + strings.TrimPrefix(ref, "refs/heads/")),
		}, nil
	case strings.HasPrefix(ref, "refs/tags/"):
		return &resolvedRef{
			kind:     resolvedRefTag,
			input:    ref,
			fullRef:  ref,
			localRef: plumbing.ReferenceName("refs/poutine/target"),
		}, nil
	}

	remote, err := repo.Remote("origin")
	if err != nil {
		return nil, fmt.Errorf("failed to get origin remote for ref resolution: %w", err)
	}

	remoteRefs, err := remote.List(&gogit.ListOptions{
		Auth: authForToken(token),
	})
	if err != nil {
		if err := classifyFetchError(err); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("failed to list remote refs for %s: %w", url, err)
	}

	tagRef := plumbing.ReferenceName("refs/tags/" + ref)
	for _, remoteRef := range remoteRefs {
		if remoteRef.Name() == tagRef {
			return &resolvedRef{
				kind:     resolvedRefTag,
				input:    ref,
				fullRef:  tagRef.String(),
				localRef: plumbing.ReferenceName("refs/poutine/target"),
			}, nil
		}
	}

	branchRef := plumbing.ReferenceName("refs/heads/" + ref)
	for _, remoteRef := range remoteRefs {
		if remoteRef.Name() == branchRef {
			return &resolvedRef{
				kind:     resolvedRefBranch,
				input:    ref,
				fullRef:  branchRef.String(),
				localRef: plumbing.ReferenceName("refs/remotes/origin/" + ref),
			}, nil
		}
	}

	return nil, fmt.Errorf("%w: %s", ErrRemoteRefNotFound, ref)
}

func resolveFetchedTargetToCommit(store storer.EncodedObjectStorer, repo *gogit.Repository, resolved *resolvedRef, token string) (plumbing.Hash, error) {
	if resolved != nil && resolved.kind != resolvedRefHead {
		return resolveFetchedRefToCommit(store, repo, resolved.localRef)
	}

	if resolved != nil && resolved.localRef != "" {
		return resolveFetchedRefToCommit(store, repo, resolved.localRef)
	}

	// For HEAD: try common default branch names from local refs (no network call)
	for _, name := range []string{"main", "master"} {
		localRef := plumbing.ReferenceName("refs/remotes/origin/" + name)
		r, err := repo.Reference(localRef, true)
		if err == nil {
			return r.Hash(), nil
		}
	}

	// Fallback: find the first remote origin ref
	refs, err := repo.References()
	if err != nil {
		return plumbing.ZeroHash, fmt.Errorf("failed to list refs: %w", err)
	}

	var headHash plumbing.Hash
	_ = refs.ForEach(func(r *plumbing.Reference) error {
		name := string(r.Name())
		if strings.HasPrefix(name, "refs/remotes/origin/") && !strings.HasSuffix(name, "/HEAD") {
			headHash = r.Hash()
			return errors.New("found")
		}
		return nil
	})
	if headHash != plumbing.ZeroHash {
		return headHash, nil
	}

	// Last resort: network call to find HEAD symref
	remote, err := repo.Remote("origin")
	if err == nil {
		remoteRefs, err := remote.List(&gogit.ListOptions{
			Auth: authForToken(token),
		})
		if err == nil {
			for _, r := range remoteRefs {
				if r.Name() == plumbing.HEAD && r.Type() == plumbing.SymbolicReference {
					defaultBranch := strings.TrimPrefix(string(r.Target()), "refs/heads/")
					localRef := plumbing.ReferenceName("refs/remotes/origin/" + defaultBranch)
					return resolveFetchedRefToCommit(store, repo, localRef)
				}
			}
		}
	}

	return plumbing.ZeroHash, fmt.Errorf("could not resolve head for ref %s", resolved.input)
}

func resolveFetchedRefToCommit(store storer.EncodedObjectStorer, repo *gogit.Repository, refName plumbing.ReferenceName) (plumbing.Hash, error) {
	r, err := repo.Reference(refName, true)
	if err != nil {
		return plumbing.ZeroHash, fmt.Errorf("failed to resolve fetched ref %s: %w", refName, err)
	}

	return peelToCommit(store, r.Hash())
}

func peelToCommit(store storer.EncodedObjectStorer, hash plumbing.Hash) (plumbing.Hash, error) {
	obj, err := store.EncodedObject(plumbing.AnyObject, hash)
	if err != nil {
		return plumbing.ZeroHash, fmt.Errorf("failed to load object %s: %w", hash, err)
	}

	switch obj.Type() {
	case plumbing.CommitObject:
		return hash, nil
	case plumbing.TagObject:
		tag, err := object.GetTag(store, hash)
		if err != nil {
			return plumbing.ZeroHash, fmt.Errorf("failed to load tag %s: %w", hash, err)
		}
		return peelToCommit(store, tag.Target)
	default:
		return plumbing.ZeroHash, fmt.Errorf("object %s is %s, expected commit or tag", hash, obj.Type())
	}
}

// looksLikeSHA returns true if s looks like a full-length git commit SHA.
// discoverDefaultBranch uses remote.List to find the HEAD symref target.
// Returns empty string if it can't be determined.
// discoverDefaultBranchFromURL does a lightweight ls-remote to find the HEAD symref.
func discoverDefaultBranchFromURL(url string, token string) string {
	store := memory.NewStorage()
	repo, err := gogit.Init(store, nil)
	if err != nil {
		return ""
	}
	_, err = repo.CreateRemote(&config.RemoteConfig{Name: "origin", URLs: []string{url}})
	if err != nil {
		return ""
	}
	remote, err := repo.Remote("origin")
	if err != nil {
		return ""
	}
	refs, err := remote.List(&gogit.ListOptions{
		Auth: authForToken(token),
	})
	if err != nil {
		return ""
	}
	for _, ref := range refs {
		if ref.Name() == plumbing.HEAD && ref.Type() == plumbing.SymbolicReference {
			return strings.TrimPrefix(string(ref.Target()), "refs/heads/")
		}
	}
	return ""
}

func looksLikeSHA(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// classifyFetchError maps go-git errors to domain errors.
func classifyFetchError(err error) error {
	if err == nil || errors.Is(err, gogit.NoErrAlreadyUpToDate) {
		return nil
	}

	var httpErr *gogithttp.Err
	if errors.As(err, &httpErr) {
		code := httpErr.StatusCode()
		if code == 401 || code == 403 || code == 404 {
			return fmt.Errorf("%w: %v", ErrRepoNotReachable, err) //nolint:errorlint
		}
	}

	if errors.Is(err, transport.ErrRepositoryNotFound) ||
		errors.Is(err, transport.ErrAuthenticationRequired) ||
		errors.Is(err, transport.ErrAuthorizationFailed) {
		return fmt.Errorf("%w: %v", ErrRepoNotReachable, err) //nolint:errorlint
	}

	if isTransientError(err) {
		return fmt.Errorf("transient network error: %w", err)
	}

	return fmt.Errorf("git fetch failed: %w", err)
}

func isTransientError(err error) bool {
	var netErr *net.OpError
	if errors.As(err, &netErr) {
		return true
	}
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	errStr := strings.ToLower(err.Error())
	transientPatterns := []string{
		"connection reset by peer",
		"broken pipe",
		"could not resolve host",
	}
	for _, pattern := range transientPatterns {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}
	return false
}

// LocalGitClient wraps go-git for local repository operations.
type LocalGitClient struct {
	GitClient *GitClient
}

func NewLocalGitClient(_ *GitCommand) *LocalGitClient {
	return &LocalGitClient{GitClient: NewGitClient(nil)}
}

func (g *LocalGitClient) Clone(ctx context.Context, clonePath string, url string, token string, ref string) error {
	log.Debug().Msgf("Local Git Client shouldn't be used to clone repositories")
	return nil
}

func (g *LocalGitClient) FetchCone(ctx context.Context, clonePath, url, token, ref, cone string) error {
	err := g.GitClient.FetchCone(ctx, clonePath, url, token, ref, cone)
	if err != nil {
		log.Debug().Err(err).Msg("failed to fetch cone for local repo")
		return nil
	}
	return nil
}

func (g *LocalGitClient) CommitSHA(clonePath string) (string, error) {
	repo, err := gogit.PlainOpen(clonePath)
	if err != nil {
		log.Debug().Err(err).Msg("failed to open local repo for commit SHA")
		return "", nil
	}
	head, err := repo.Head()
	if err != nil {
		log.Debug().Err(err).Msg("failed to get HEAD for local repo")
		return "", nil
	}
	return head.Hash().String(), nil
}

func (g *LocalGitClient) LastCommitDate(ctx context.Context, clonePath string) (time.Time, error) {
	repo, err := gogit.PlainOpen(clonePath)
	if err != nil {
		log.Debug().Err(err).Msg("failed to open local repo for last commit date")
		return time.Now(), nil
	}
	head, err := repo.Head()
	if err != nil {
		log.Debug().Err(err).Msg("failed to get HEAD for local repo")
		return time.Now(), nil
	}
	commit, err := repo.CommitObject(head.Hash())
	if err != nil {
		log.Debug().Err(err).Msg("failed to get commit for local repo")
		return time.Now(), nil
	}
	return commit.Committer.When, nil
}

func (g *LocalGitClient) GetRemoteOriginURL(ctx context.Context, repoPath string) (string, error) {
	repo, err := gogit.PlainOpen(repoPath)
	if err != nil {
		log.Debug().Err(err).Msg("failed to open local repo for remote URL")
		return repoPath, nil
	}
	remote, err := repo.Remote("origin")
	if err != nil {
		log.Debug().Err(err).Msg("failed to get origin remote for local repo")
		return repoPath, nil
	}
	urls := remote.Config().URLs
	if len(urls) == 0 {
		return repoPath, nil
	}
	return urls[0], nil
}

func (g *LocalGitClient) GetRepoHeadBranchName(ctx context.Context, repoPath string) (string, error) {
	repo, err := gogit.PlainOpen(repoPath)
	if err != nil {
		log.Debug().Err(err).Msg("failed to open local repo for branch name")
		return "local", nil
	}
	head, err := repo.Head()
	if err != nil {
		log.Debug().Err(err).Msg("failed to get HEAD for local repo")
		return "local", nil
	}
	if head.Name().IsBranch() {
		return head.Name().Short(), nil
	}
	return "local", nil
}

func (g *LocalGitClient) GetUniqWorkflowsBranches(ctx context.Context, clonePath string) (map[string][]models.BranchInfo, error) {
	branchInfo, err := g.GitClient.GetUniqWorkflowsBranches(ctx, clonePath)
	if err != nil {
		log.Debug().Err(err).Msg("failed to get unique workflows for local repo")
		return nil, nil
	}
	return branchInfo, nil
}

func (g *LocalGitClient) BlobMatches(ctx context.Context, clonePath, blobSha string, re *regexp.Regexp) (bool, []byte, error) {
	match, content, err := g.GitClient.BlobMatches(ctx, clonePath, blobSha, re)
	if err != nil {
		log.Debug().Err(err).Msg("failed to blob match for local repo")
		return false, nil, nil
	}
	return match, content, nil
}

func (g *LocalGitClient) ListFiles(clonePath string, extensions []string) (map[string][]byte, error) {
	repo, err := gogit.PlainOpen(clonePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open local repo: %w", err)
	}
	head, err := repo.Head()
	if err != nil {
		return nil, fmt.Errorf("failed to get HEAD: %w", err)
	}
	commit, err := repo.CommitObject(head.Hash())
	if err != nil {
		return nil, fmt.Errorf("failed to get commit: %w", err)
	}
	tree, err := commit.Tree()
	if err != nil {
		return nil, fmt.Errorf("failed to get tree: %w", err)
	}

	extSet := make(map[string]struct{}, len(extensions))
	for _, ext := range extensions {
		extSet[ext] = struct{}{}
	}

	files := make(map[string][]byte)
	iter := tree.Files()
	err = iter.ForEach(func(f *object.File) error {
		matched := len(extensions) == 0
		if !matched {
			for ext := range extSet {
				if strings.HasSuffix(f.Name, ext) {
					matched = true
					break
				}
			}
		}
		if !matched {
			return nil
		}
		content, err := f.Contents()
		if err != nil {
			log.Debug().Err(err).Str("file", f.Name).Msg("failed to read file contents")
			return nil
		}
		files[f.Name] = []byte(content)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to iterate files: %w", err)
	}
	return files, nil
}

func (g *LocalGitClient) Cleanup(clonePath string) {
	// No-op for local repos
}
