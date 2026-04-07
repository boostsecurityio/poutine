package analyze

import "github.com/boostsecurityio/poutine/models"

// ProgressObserver receives structured progress events during analysis.
// All methods must be non-blocking — implementations should not perform
// expensive I/O or hold locks for extended periods.
//
// # Concurrency
//
// During AnalyzeOrg, methods are called from two contexts:
//
// Main goroutine (sequential, never concurrent with each other):
//   - OnDiscoveryCompleted
//   - OnRepoSkipped
//   - OnFinalizeStarted
//   - OnFinalizeCompleted
//
// Worker goroutines (called concurrently from multiple goroutines):
//   - OnRepoStarted
//   - OnRepoCompleted
//   - OnRepoError
//
// Implementations MUST ensure that the worker-goroutine methods are
// goroutine-safe. Note that worker methods may also run concurrently
// with the main-goroutine methods above.
//
// During AnalyzeRepo and AnalyzeStaleBranches all methods are called
// from a single goroutine.
type ProgressObserver interface {
	// OnDiscoveryCompleted is called from the main goroutine when the
	// total repo count is known (first batch with TotalCount > 0).
	OnDiscoveryCompleted(org string, totalCount int)

	// OnRepoStarted is called from a worker goroutine when analysis
	// of a repo begins. Must be goroutine-safe.
	OnRepoStarted(repo string)

	// OnRepoCompleted is called from a worker goroutine when a repo
	// finishes successfully. Must be goroutine-safe.
	OnRepoCompleted(repo string, pkg *models.PackageInsights)

	// OnRepoError is called from a worker goroutine when a repo
	// analysis fails (non-fatal). Must be goroutine-safe.
	OnRepoError(repo string, err error)

	// OnRepoSkipped is called from the main goroutine when a repo is
	// skipped (fork, empty, etc.).
	OnRepoSkipped(repo string, reason string)

	// OnFinalizeStarted is called from the main goroutine when the
	// formatting/output phase begins, after all repos are processed.
	OnFinalizeStarted(totalPackages int)

	// OnFinalizeCompleted is called from the main goroutine when
	// formatting is done.
	OnFinalizeCompleted()
}

type noopObserver struct{}

func (noopObserver) OnDiscoveryCompleted(string, int)                {}
func (noopObserver) OnRepoStarted(string)                            {}
func (noopObserver) OnRepoCompleted(string, *models.PackageInsights) {}
func (noopObserver) OnRepoError(string, error)                       {}
func (noopObserver) OnRepoSkipped(string, string)                    {}
func (noopObserver) OnFinalizeStarted(int)                           {}
func (noopObserver) OnFinalizeCompleted()                            {}
