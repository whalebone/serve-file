# build image
FROM golang:1.21-alpine as build

ARG GH_USERNAME
ARG GH_TOKEN
ARG GIT_COMMIT
ARG VERSION

# set the Current Working Directory inside the build container
WORKDIR /build

# Create appuser.
ENV USER=appuser
ENV UID=10001
# See https://stackoverflow.com/a/55757473/12429735RUN
RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    "${USER}"

# copy go mod and sum files
COPY go.mod go.sum ./

# download all dependencies; dependencies will be cached if the go.mod and go.sum files are not changed
# install ca-certificates to allow external tls connections
RUN apk add --no-cache ca-certificates && \
    go mod download && go mod verify

# copy sources
COPY . .

# build the Go app, -w -s to strip debug info
RUN export GO_MOD=$(go list -m); mkdir binary && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X '${GO_MOD}/app.Version=${VERSION}' \
        -X '${GO_MOD}/app.GitCommit=${GIT_COMMIT}'" \
    -o /build/binary/app ./server.go

# runtime image
FROM scratch

COPY --from=build /etc/passwd /etc/passwd
COPY --from=build /etc/group /etc/group
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

COPY --from=build /build/binary/app .

USER appuser:appuser

# Add port if service
EXPOSE 8443

ENTRYPOINT ["/app"]
