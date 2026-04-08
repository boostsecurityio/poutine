package analyze

import (
	"os"

	"github.com/boostsecurityio/poutine/models"
	"github.com/schollz/progressbar/v3"
)

// ProgressBarObserver implements ProgressObserver by rendering a CLI progress bar.
// For org analysis it shows a repo-count bar (created on OnDiscoveryCompleted).
// For single-repo analysis it shows a step-level bar (created on first OnStepCompleted).
type ProgressBarObserver struct {
	bar   *progressbar.ProgressBar
	quiet bool
}

func NewProgressBarObserver(quiet bool) *ProgressBarObserver {
	return &ProgressBarObserver{quiet: quiet}
}

func (o *ProgressBarObserver) newBar(max int64, description string) *progressbar.ProgressBar {
	if o.quiet {
		return progressbar.DefaultSilent(max, description)
	}
	return progressbar.NewOptions64(max,
		progressbar.OptionSetDescription(description),
		progressbar.OptionShowCount(),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionClearOnFinish(),
	)
}

func (o *ProgressBarObserver) OnAnalysisStarted(description string) {
	// Create an indeterminate spinner bar (max=-1) to show activity
	// before the total count is known or the first step completes.
	o.bar = o.newBar(-1, description)
	_ = o.bar.RenderBlank()
}

func (o *ProgressBarObserver) OnDiscoveryCompleted(_ string, totalCount int) {
	// Finish the spinner before replacing with a counting bar.
	if o.bar != nil {
		_ = o.bar.Finish()
	}
	o.bar = o.newBar(int64(totalCount), "Analyzing repositories")
}

func (o *ProgressBarObserver) OnRepoStarted(_ string) {}

func (o *ProgressBarObserver) OnRepoCompleted(_ string, _ *models.PackageInsights) {
	if o.bar != nil {
		_ = o.bar.Add(1)
	}
}

func (o *ProgressBarObserver) OnRepoError(_ string, _ error) {
	if o.bar != nil {
		_ = o.bar.Add(1)
	}
}

func (o *ProgressBarObserver) OnRepoSkipped(_ string, _ string) {
	if o.bar != nil {
		if newMax := o.bar.GetMax() - 1; newMax >= 0 {
			o.bar.ChangeMax(newMax)
		}
	}
}

func (o *ProgressBarObserver) OnStepCompleted(description string) {
	if o.bar != nil && o.bar.GetMax64() == -1 {
		// Finish the spinner, then create a step bar.
		_ = o.bar.Finish()
		o.bar = nil
	}
	if o.bar == nil {
		// First step — create the bar.
		o.bar = o.newBar(1, description)
	} else {
		// Grow the bar to accommodate each new step, then advance.
		o.bar.ChangeMax(o.bar.GetMax() + 1)
		o.bar.Describe(description)
	}
	_ = o.bar.Add(1)
}

func (o *ProgressBarObserver) OnFinalizeStarted(_ int) {
	if o.bar != nil {
		_ = o.bar.Finish()
	}
}

func (o *ProgressBarObserver) OnFinalizeCompleted() {}
