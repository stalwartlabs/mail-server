FROM debian:bullseye-slim 

RUN apt-get update -y && apt-get install -yq ca-certificates curl

COPY resources/docker/configure.sh /usr/local/bin/configure.sh
COPY resources/docker/entrypoint.sh /usr/local/bin/entrypoint.sh

RUN sed -i -e 's/__C__/all-in-one/g' /usr/local/bin/configure.sh && \
    sed -i -e 's/__R__/mail-server/g' /usr/local/bin/configure.sh && \
    sed -i -e 's/__N__/mail/g' /usr/local/bin/configure.sh && \
    sed -i -e 's/__B__/stalwart-mail/g' /usr/local/bin/entrypoint.sh

RUN chmod a+rx /usr/local/bin/*.sh

RUN /usr/local/bin/configure.sh --download

RUN useradd stalwart-mail -s /sbin/nologin -M
RUN mkdir -p /opt/stalwart-mail
RUN chown stalwart-mail:stalwart-mail /opt/stalwart-mail

VOLUME [ "/opt/stalwart-mail" ]

EXPOSE	443 25 587 465 143 993 4190

ENTRYPOINT ["/bin/sh", "/usr/local/bin/entrypoint.sh"]
