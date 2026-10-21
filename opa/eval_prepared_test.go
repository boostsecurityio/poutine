package opa

import (
	"context"
	"sync"
	"testing"

	"github.com/boostsecurityio/poutine/models"
	"github.com/boostsecurityio/poutine/results"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests pin the invariants that Eval's cached query plan must preserve:
//
//  1. The same query on the same Opa, evaluated with DIFFERENT inputs, must
//     return per-input-correct results — input must stay per-eval and must never
//     be baked into a cached plan.
//  2. Concurrent Eval calls on a shared Opa (as AnalyzeOrg does across repo
//     goroutines) must be race-free and correct.
//  3. Config changes (WithConfig) and rule-set changes (Compile) must be
//     reflected by subsequent Evals — a stale cached plan bound to the old
//     compiler would be a regression.

func TestEvalSameQueryDifferentInputs(t *testing.T) {
	o, err := NewOpa(context.TODO(), &models.Config{Include: []models.ConfigInclude{}})
	noOpaErrors(t, err)
	ctx := context.TODO()

	// Reuse the exact same query string across calls, varying only the input.
	const q = `utils.job_uses_self_hosted_runner(input)`
	cases := map[string]bool{
		"self-hosted":   true,
		"ubuntu-latest": false,
		"random-name":   true,
		"windows-2022":  false,
	}
	// Run each case twice, interleaved, to catch any input carried across calls.
	for pass := 0; pass < 2; pass++ {
		for runner, want := range cases {
			var got bool
			err := o.Eval(ctx, q, map[string]interface{}{"runs_on": []string{runner}}, &got)
			noOpaErrors(t, err)
			assert.Equal(t, want, got, "runner=%s pass=%d", runner, pass)
		}
	}
}

func TestEvalConcurrentSharedOpa(t *testing.T) {
	o, err := NewOpa(context.TODO(), &models.Config{Include: []models.ConfigInclude{}})
	noOpaErrors(t, err)
	ctx := context.TODO()

	const q = `utils.job_uses_self_hosted_runner(input)`
	type tc struct {
		runner string
		want   bool
	}
	cases := []tc{
		{"self-hosted", true},
		{"ubuntu-latest", false},
		{"random-name", true},
		{"windows-2019", false},
	}

	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		c := cases[i%len(cases)]
		wg.Add(1)
		go func(c tc) {
			defer wg.Done()
			var got bool
			if err := o.Eval(ctx, q, map[string]interface{}{"runs_on": []string{c.runner}}, &got); err != nil {
				t.Errorf("eval error: %v", err)
				return
			}
			assert.Equal(t, c.want, got, "runner=%s", c.runner)
		}(c)
	}
	wg.Wait()
}

func TestEvalReflectsRecompile(t *testing.T) {
	o, err := NewOpa(context.TODO(), &models.Config{Include: []models.ConfigInclude{}})
	noOpaErrors(t, err)
	ctx := context.TODO()

	const q = `data.rules.pr_runs_on_self_hosted.rule`

	var before *results.Rule
	err = o.Eval(ctx, q, nil, &before)
	noOpaErrors(t, err)
	require.NotNil(t, before)
	assert.Equal(t, []interface{}{}, before.Config["allowed_runners"].Value)

	// Change config (which rewrites the store) and recompile the modules.
	err = o.WithConfig(ctx, &models.Config{
		RulesConfig: map[string]map[string]interface{}{
			"pr_runs_on_self_hosted": {"allowed_runners": []string{"self-hosted"}},
		},
	})
	require.NoError(t, err)
	require.NoError(t, o.Compile(ctx, nil, nil))

	// The same query on the same Opa must now reflect the new config, not a
	// stale cached result/plan.
	var after *results.Rule
	err = o.Eval(ctx, q, nil, &after)
	noOpaErrors(t, err)
	require.NotNil(t, after)
	assert.Equal(t, []interface{}{"self-hosted"}, after.Config["allowed_runners"].Value)
}

// TestEvalRecompileInvalidatesCache specifically guards the cache-invalidation in
// Compile. Unlike TestEvalReflectsRecompile (whose config change is read from the
// store on every eval and so would pass even without invalidation), this changes
// the *rule set*: it primes the cache with a query against a rule, then recompiles
// with that rule skipped. A cached plan bound to the old compiler would still
// resolve the rule; a correctly invalidated cache re-prepares and the rule is
// gone. This test FAILS if the invalidation in Compile is removed.
func TestEvalRecompileInvalidatesCache(t *testing.T) {
	o, err := NewOpa(context.TODO(), &models.Config{Include: []models.ConfigInclude{}})
	noOpaErrors(t, err)
	ctx := context.TODO()

	const q = `data.rules.pr_runs_on_self_hosted.rule`

	// Prime the cache: the rule resolves.
	var before *results.Rule
	require.NoError(t, o.Eval(ctx, q, nil, &before))
	require.NotNil(t, before)

	// Recompile with the rule skipped → new compiler, rule removed from the set.
	require.NoError(t, o.Compile(ctx, []string{"pr_runs_on_self_hosted"}, nil))

	// With a correctly invalidated cache, the query now resolves to nothing and
	// Eval reports the empty result set. A stale plan would still succeed.
	var after *results.Rule
	err = o.Eval(ctx, q, nil, &after)
	require.Error(t, err, "skipped rule must not resolve after recompile; stale cache would still find it")
}
