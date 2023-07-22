FROM debian:bullseye-slim 

RUN apt-get update -y && apt-get install -yq ca-certificates curl tar

COPY resources/docker/configure.sh /usr/local/bin/configure.sh
COPY resources/docker/entrypoint.sh /usr/local/bin/entrypoint.sh

RUN chmod a+rx /usr/local/bin/*.sh

RUN useradd stalwart-mail -s /sbin/nologin -M
RUN mkdir -p /opt/stalwart-mail
RUN chown stalwart-mail:stalwart-mail /opt/stalwart-mail

EXPOSE	8080 25 587 465 8686 143 993 4190

ENTRYPOINT ["/bin/sh", "/usr/local/bin/entrypoint.sh"]
