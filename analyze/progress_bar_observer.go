package analyze

import (
	"os"

	"github.com/boostsecurityio/poutine/models"
	"github.com/schollz/progressbar/v3"
)

// ProgressBarObserver implements ProgressObserver by rendering a CLI progress bar.
type ProgressBarObserver struct {
	bar   *progressbar.ProgressBar
	quiet bool
}

func NewProgressBarObserver(quiet bool) *ProgressBarObserver {
	var bar *progressbar.ProgressBar
	if quiet {
		bar = progressbar.DefaultSilent(0, "Analyzing repositories")
	} else {
		bar = progressbar.NewOptions64(0,
			progressbar.OptionSetDescription("Analyzing repositories"),
			progressbar.OptionShowCount(),
			progressbar.OptionSetWriter(os.Stderr),
			progressbar.OptionClearOnFinish(),
		)
	}
	return &ProgressBarObserver{bar: bar, quiet: quiet}
}

func (o *ProgressBarObserver) OnDiscoveryCompleted(_ string, totalCount int) {
	o.bar.ChangeMax(totalCount)
}

func (o *ProgressBarObserver) OnRepoStarted(_ string) {}

func (o *ProgressBarObserver) OnRepoCompleted(_ string, _ *models.PackageInsights) {
	_ = o.bar.Add(1)
}

func (o *ProgressBarObserver) OnRepoError(_ string, _ error) {
	_ = o.bar.Add(1)
}

func (o *ProgressBarObserver) OnRepoSkipped(_ string, _ string) {
	o.bar.ChangeMax(o.bar.GetMax() - 1)
}

func (o *ProgressBarObserver) OnFinalizeStarted(_ int) {
	_ = o.bar.Finish()
}

func (o *ProgressBarObserver) OnFinalizeCompleted() {}

// ProgressBarForSteps creates a step-counting progress bar for single-repo operations.
func (o *ProgressBarObserver) ProgressBarForSteps(steps int64, description string) *progressbar.ProgressBar {
	if o.quiet {
		return progressbar.DefaultSilent(steps, description)
	}
	return progressbar.NewOptions64(steps,
		progressbar.OptionSetDescription(description),
		progressbar.OptionShowCount(),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionClearOnFinish(),
	)
}
