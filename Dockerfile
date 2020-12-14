FROM ubuntu:trusty

RUN apt-get update && apt-get install build-essential -y

ADD https://www.openssl.org/source/old/1.0.1/openssl-1.0.1f.tar.gz /builddir/
ADD https://nginx.org/download/nginx-1.10.2.tar.gz /builddir/

WORKDIR /builddir/
RUN tar xf openssl-1.0.1f.tar.gz
RUN tar xf nginx-1.10.2.tar.gz

WORKDIR /builddir/nginx-1.10.2
RUN ./configure --with-http_ssl_module --prefix=/usr/local/nginx/ --without-http_gzip_module --with-openssl=/builddir/openssl-1.0.1f --without-pcre --with-threads --without-http_rewrite_module && make && make install

WORKDIR /builddir/openssl-1.0.1f
RUN ./config && make && make install_sw

RUN mkdir /workdir/
WORKDIR /workdir
RUN mkdir certs
RUN /usr/local/ssl/bin/openssl req -x509 -newkey rsa:2048 -keyout certs/key.pem -out certs/cert.pem -days 365 -nodes -subj "/C=ES/ST=Madrid/L=Leganes/O=UC3M/OU=SSE/CN=poc.heartbleed.sse.uc3m.es"

ADD nginx.conf /usr/local/nginx/conf/
RUN echo "admin135:$(/usr/local/ssl/bin/openssl passwd secret)" > /workdir/htpasswd

EXPOSE 443

CMD echo "Vulnerable Nginx server (OpenSSL 1.0.1f) started on port 443" && /usr/local/nginx/sbin/nginx
