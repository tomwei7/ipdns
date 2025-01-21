FROM golang:1.23-bookworm
COPY . /workspace/ipdns
WORKDIR /workspace/ipdns
RUN make all
FROM alpine:3
RUN apk add --no-cache gcompat
COPY --from=0 /workspace/ipdns/bin/ipdns /ipdns
EXPOSE 5353/udp
ENTRYPOINT ["/ipdns"]
