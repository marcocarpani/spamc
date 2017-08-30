FROM alpine:3.6

EXPOSE 783

# sa-update will choke on busybox's wget, so install GNU's version for that too.
RUN apk update
RUN apk add spamassassin wget

# Setup user
RUN adduser -h /var/lib/spamassassin -s /bin/false -S _spamd
RUN chown -R _spamd /var/lib/spamassassin

# Run spamd
RUN sa-update
CMD spamd \
	--syslog stderr \
	--username _spamd \
	--helper-home-dir /var/lib/spamassassin \
	--allow-tell \
	--allowed-ips '127.,172.,192.,10.' \
	--create-prefs \
	--nouser-config \
	--listen 0.0.0.0:783 \
