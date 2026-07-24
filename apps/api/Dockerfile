FROM golang:1.26.5-alpine AS build
WORKDIR /src
RUN apk add --no-cache ca-certificates git
COPY go.mod ./
COPY apps ./apps
COPY internal ./internal
COPY packages ./packages
COPY tests ./tests
RUN go mod tidy && go test ./apps/... ./internal/... ./packages/...
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/cve-atlas-api ./apps/api/cmd/server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/cve-atlas-api /cve-atlas-api
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/cve-atlas-api"]
