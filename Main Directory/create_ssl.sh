# Generate and Configure SSL Keys for secure mySQL connections

# Reference: https://lowendbox.com/blog/getting-started-with-mysql-over-ssl/

# Create clean environment
rm -rf newcerts
mkdir newcerts && cd newcerts

#generate the CA certificate and private key.
openssl genrsa 2048 > ca-key.pem

#generate the certificate using that key
openssl req -sha1 -new -x509 -nodes -days 3650 -key ca-key.pem > ca-cert.pem

#create a private key for the server and a signing request to go with that
openssl req -sha1 -newkey rsa:2048 -days 730 -nodes -keyout server-key.pem > server-req.pem

#export the private key into an RSA private key
openssl rsa -in server-key.pem -out server-key.pem

#create a certificate using the CA certificate
openssl x509 -sha1 -req -in server-req.pem -days 730 -CA ca-cert.pem -CAkey ca-key.pem -set_serial 01 > server-cert.pem

# Client key gen

#a private key and a certificate signing request
openssl req -sha1 -newkey rsa:2048 -days 730 -nodes -keyout client-key.pem > client-req.pem

#export the private key to an RSA private key
openssl rsa -in client-key.pem -out client-key.pem

#create a certificate using the CA private key and certificate
openssl x509 -sha1 -req -in client-req.pem -days 730 -CA ca-cert.pem -CAkey ca-key.pem -set_serial 01 > client-cert.pem

