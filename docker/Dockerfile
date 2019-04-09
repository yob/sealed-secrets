FROM alpine
MAINTAINER Angus Lees <gus@inodes.org>
RUN apk update && apk add ca-certificates && rm -rf /var/cache/apk/*
COPY controller /usr/local/bin/

EXPOSE 8080
ENTRYPOINT ["controller"]
