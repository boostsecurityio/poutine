ARG GIT=cgr.dev/chainguard/git:latest@sha256:06119871a608d163eac2daddd0745582e457a29ee8402bd351c13f294ede30e1
ARG GORELEASER=ghcr.io/goreleaser/goreleaser:v2.3.1@sha256:6835c0b61b746bf4b2e036e262d3c5c32029ebb079eb42911bffa84b1b5c8008

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
