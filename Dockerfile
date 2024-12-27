FROM alpine:latest

RUN apk update && apk --no-interactive upgrade && apk add --no-cache \
	openssl \
	openssl-dev \
	musl-dev \
	bsd-compat-headers \
	shadow \
	git \
	make \
	gcc

# Modify this to set a proper hostname
ENV HN=g.local

RUN git clone https://github.com/thexhr/twind && cd twind && make all user install setuptls

# Modify this here accordingly to copy your static files over
COPY . /var/twind/$HN

EXPOSE 1965

CMD [ "twind" , "-f" ]
