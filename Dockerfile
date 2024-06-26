ARG GIT=cgr.dev/chainguard/git:latest@sha256:06119871a608d163eac2daddd0745582e457a29ee8402bd351c13f294ede30e1
ARG GORELEASER=ghcr.io/goreleaser/goreleaser:v2.0.1@sha256:c1d6c5a07be6d0f7472461e2ec578beaa4a51c12bb03a8e34d3e73730b4aa32a

FROM ${GORELEASER} as goreleaser
WORKDIR /app
COPY . .
RUN goreleaser build --snapshot --single-target
RUN mv dist/*/poutine /usr/bin/poutine

FROM ${GIT} as base
WORKDIR /src
RUN git config --global --add safe.directory /src

FROM base as poutine
COPY --from=goreleaser /usr/bin/poutine /usr/bin/poutine
ENTRYPOINT ["/usr/bin/poutine"]
