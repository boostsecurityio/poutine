package poutine.utils

import rego.v1

unpinned_github_action(purl) if {
	startswith(purl, "pkg:githubactions/")
	contains(purl, "@")
	not regex.match("@[a-f0-9]{40}", purl)
}

unpinned_docker(purl) if {
	startswith(purl, "pkg:docker/")
	not contains(purl, "@")
	not regex.match("@sha256:[a-f0-9]{64}", purl)
}

unpinned_purl(purl) if {
	unpinned_github_action(purl)
} else if {
	unpinned_docker(purl)
}

find_pr_checkouts(workflow) := xs if {
	xs := {{"job_idx": j, "step_idx": i, "workflow": workflow} |
		s := workflow.jobs[j].steps[i]
		startswith(s.uses, "actions/checkout@")
		contains(s.with_ref, "${{")
	} | {{"job_idx": j, "step_idx": i, "workflow": workflow} |
		s := workflow.jobs[j].steps[i]
		regex.match("gh pr checkout ", s.run)
	}
}

workflow_steps_after(options) := steps if {
	steps := {{"step": s, "job_idx": options.job_idx, "step_idx": k} |
		s := options.workflow.jobs[options.job_idx].steps[k]
		k > options.step_idx
	}
}

filter_workflow_events(workflow, only) if {
	workflow.events[_].name == only[_]
}

job_uses_self_hosted_runner(job) if {
	run_on := job.runs_on[_]
	not contains(run_on, "$") # skip expressions
	not regex.match(
		"(?i)^((ubuntu-(([0-9]{2})\\.04|latest(-(4|8|16)-cores)?)|macos-([0-9]{2}|latest)(-x?large)?|windows-(20[0-9]{2}|latest(-8-cores)?)|(buildjet|warp)-[a-z0-9-]+))$",
		run_on,
	)
} else := false

empty(xs) if {
	xs == null
} else if {
	count(xs) == 0
}

workflow_run_parents(pkg, workflow) = parents if {
	parent_names = {name |
		event := workflow.events[_]
		event.name == "workflow_run"
		name := event.workflows[_]
	}
	parents := {parent |
		parent := pkg.github_actions_workflows[_]
		glob.match(parent_names[_], ["/"], parent.name)
	}
}

to_set(xs) = xs if {
	is_set(xs)
} else := {v | v := xs[_]} if {
	is_array(xs)
} else := {xs}

########################################################################
# job order utils
########################################################################

job_steps_after(options) := steps if {
	steps := {{"step": s, "step_idx": k} |
		s := options.job.steps[k]
		k > options.step_idx
	}
}

job_steps_before(options) := steps if {
	steps := {{"step": s, "step_idx": k} |
		s := options.job.steps[k]
		k < options.step_idx
	}
}


########################################################################
# find_first_uses_in_job
########################################################################

find_first_uses_in_job(job, uses) := xs if {
	xs := {{"job": job, "step_idx": i} |
		s := job.steps[i]
		startswith(s.uses, sprintf("%v@", [uses[_]]))
	}
}