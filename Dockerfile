FROM golang:1.20 as build

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY . ./
RUN --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 go build -ldflags="-w -s" -o bin/ ./tunwgs ./tunwg

FROM alpine as upx

RUN apk add --no-cache upx

COPY --from=build /app/bin/ /app/bin/
RUN upx --best /app/bin/*

FROM alpine

RUN apk add -U --no-cache ca-certificates

COPY --from=build /app/bin/ /bin/
# COPY --from=upx /app/bin/ /bin/

VOLUME /data
ENV TUNWG_PATH=/data

CMD ["/bin/tunwg"]