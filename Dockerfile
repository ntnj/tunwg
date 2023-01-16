FROM golang:1.20 as build

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY . ./
RUN --mount=type=cache,target=/root/.cache/go-build go build -o /bin/ ./tunwgs ./tunwg

FROM ubuntu

RUN apt-get update && apt-get install -y ca-certificates --no-install-recommends
COPY --from=build /bin/ /bin/

VOLUME /data
ENV TUNWG_PATH=/data

CMD ["/bin/tunwg"]