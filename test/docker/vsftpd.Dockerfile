FROM alpine:3.20
RUN apk add --no-cache vsftpd \
 && adduser -D -h /home/ftpuser ftpuser \
 && echo 'ftpuser:ftppass' | chpasswd \
 && mkdir -p /home/ftpuser/upload /var/run/vsftpd/empty \
 && chown ftpuser:ftpuser /home/ftpuser/upload
CMD ["vsftpd", "/etc/vsftpd/vsftpd.conf"]
