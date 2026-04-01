package analyze_test

import (
	"context"
	"os"
	"runtime"
	"syscall"
	"testing"

	"github.com/boostsecurityio/poutine/analyze"
	"github.com/boostsecurityio/poutine/formatters/noop"
	"github.com/boostsecurityio/poutine/models"
	"github.com/boostsecurityio/poutine/opa"
	"github.com/boostsecurityio/poutine/providers/gitops"
	"github.com/boostsecurityio/poutine/providers/scm"
	"github.com/rs/zerolog"
)

func timevalToMs(tv syscall.Timeval) float64 {
	return float64(tv.Sec)*1000 + float64(tv.Usec)/1000
}

func normalizeMaxRSS(rssValue int64) float64 {
	if runtime.GOOS == "linux" {
		return float64(rssValue) * 1024
	}
	return float64(rssValue)
}

type resourceSnapshot struct {
	mem     runtime.MemStats
	ruSelf  syscall.Rusage
	ruChild syscall.Rusage
}

func captureSnapshot() resourceSnapshot {
	var s resourceSnapshot
	runtime.ReadMemStats(&s.mem)
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &s.ruSelf)
	_ = syscall.Getrusage(syscall.RUSAGE_CHILDREN, &s.ruChild)
	return s
}

func reportMetrics(b *testing.B, before, after resourceSnapshot) {
	cpuSelfMs := (timevalToMs(after.ruSelf.Utime) - timevalToMs(before.ruSelf.Utime)) +
		(timevalToMs(after.ruSelf.Stime) - timevalToMs(before.ruSelf.Stime))
	cpuChildrenMs := (timevalToMs(after.ruChild.Utime) - timevalToMs(before.ruChild.Utime)) +
		(timevalToMs(after.ruChild.Stime) - timevalToMs(before.ruChild.Stime))

	b.ReportMetric(cpuSelfMs, "cpu-self-ms/op")
	b.ReportMetric(cpuChildrenMs, "cpu-children-ms/op")
	b.ReportMetric(normalizeMaxRSS(after.ruSelf.Maxrss)/1024/1024, "rss-self-MB/op")
	b.ReportMetric(normalizeMaxRSS(after.ruChild.Maxrss)/1024/1024, "rss-children-MB/op")
	b.ReportMetric(float64(after.mem.HeapInuse)/1024/1024, "heap-inuse-MB/op")
	b.ReportMetric(float64(after.mem.Sys)/1024/1024, "sys-MB/op")
}

func setupAnalyzer(b *testing.B, command string) *analyze.Analyzer {
	token := os.Getenv("GH_TOKEN")
	if token == "" {
		b.Skip("GH_TOKEN not set, skipping benchmark")
	}

	zerolog.SetGlobalLevel(zerolog.WarnLevel)

	ctx := context.Background()

	scmClient, err := scm.NewScmClient(ctx, "github", "", token, command)
	if err != nil {
		b.Fatalf("failed to create SCM client: %v", err)
	}

	config := models.DefaultConfig()
	config.Quiet = false

	opaClient, err := opa.NewOpa(ctx, config)
	if err != nil {
		b.Fatalf("failed to create OPA client: %v", err)
	}

	return analyze.NewAnalyzer(scmClient, gitops.NewGitClient(nil), &noop.Format{}, config, opaClient)
}

func BenchmarkAnalyzeOrg(b *testing.B) {
	analyzer := setupAnalyzer(b, "analyze_org")
	ctx := context.Background()
	threads := 2

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		runtime.GC()
		before := captureSnapshot()

		packages, err := analyzer.AnalyzeOrg(ctx, "microsoft", &threads)
		if err != nil {
			b.Fatalf("AnalyzeOrg failed: %v", err)
		}

		after := captureSnapshot()
		reportMetrics(b, before, after)
		b.ReportMetric(float64(len(packages)), "repos/op")
	}
}

func BenchmarkAnalyzeRepo(b *testing.B) {
	analyzer := setupAnalyzer(b, "analyze_repo")
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		runtime.GC()
		before := captureSnapshot()

		pkg, err := analyzer.AnalyzeRepo(ctx, "messypoutine/gha-playground", "HEAD")
		if err != nil {
			b.Fatalf("AnalyzeRepo failed: %v", err)
		}

		after := captureSnapshot()
		reportMetrics(b, before, after)
		b.ReportMetric(float64(len(pkg.FindingsResults.Findings)), "findings/op")
	}
}
