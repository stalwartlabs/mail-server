FROM debian:bullseye-slim 

RUN apt-get update -y && apt-get install -yq ca-certificates curl

COPY resources/docker/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY resources/docker/download.sh /usr/local/bin/download.sh
RUN chmod a+rx /usr/local/bin/*.sh
RUN /usr/local/bin/download.sh
RUN rm /usr/local/bin/download.sh

RUN useradd stalwart-mail -s /sbin/nologin -M
RUN mkdir -p /opt/stalwart-mail
RUN chown stalwart-mail:stalwart-mail /opt/stalwart-mail

VOLUME [ "/opt/stalwart-mail" ]

EXPOSE	443 25 587 465 143 993 4190 8080

ENTRYPOINT ["/bin/sh", "/usr/local/bin/entrypoint.sh"]
