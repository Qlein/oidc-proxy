# Oidc-proxy

Simpliest OpenID Connect reverse proxy (based on apache vert.x reverse proxy) for bearer token
validation (based on Nimbus JOSE + JWT).


## How to build =)

>mvn clean package
 
## How to run

### Java

As this application is mainly targeted for execution in a kubernetes cluster the only option  
to set configuration value is to set the env variables:

- OIDC_PROXY_BACKEND_HOST: hostname or IP address of the upstream service
- OIDC_PROXY_BACKEND_PORT: port number of upstream service
- OIDC_PROXY_PORT: proxy port to listen
- OIDC_PROXY_REALM_URL: Full OpenID Connect realm URL

After the application is built and env vars are set just run the application as usual:

> java -jar target/oidc-proxy-VERSION.jar

### Docker

Example configuration running proxy on port 8081 and forwarding validated requests to the backend at 127.0.0.1:8082 with oidc realm URL http://localhost:8080/auth/realms/master

> docker run -p 8081:8081 -e OIDC_PROXY_BACKEND_HOST=127.0.0.1 -e OIDC_PROXY_BACKEND_PORT=8082 -e OIDC_PROXY_PORT=8081 -e OIDC_PROXY_REALM_URL=http://localhost:8080/auth/realms/master qlein/oidc-reverse-proxy

### Credits:

- [Qlein.dev](https://qlein.dev)



