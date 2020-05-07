FROM golang:alpine

RUN apk update && apk add sqlite git gcc libc-dev bash

RUN mkdir /apps
COPY src/ /apps/
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
RUN go get -t github.com/sirupsen/logrus
RUN go get -t github.com/mattn/go-sqlite3
RUN go get -t gopkg.in/macaron.v1
RUN go get -t github.com/alecthomas/kingpin
RUN go get -t golang.org/x/crypto/ssh

WORKDIR /apps
RUN go build -o api api.go
RUN go build -o honeypot main.go server.go attempts.go

EXPOSE 22 4000

#CMD ["./honeypot","--listen","0.0.0.0:22"]
ENTRYPOINT ["/entrypoint.sh"]
