gcc -Wall -Werror antivirus.c -I/usr/include/mysql blacklist.c dboperations.c getSha256.c -lm $(mysql_config --libs) -lcrypto -lssl -o antivirus

gcc -Wall -Werror dbwhitelist.c -I/usr/include/mysql getSha256.c dboperations.c -lm $(mysql_config --libs) -lcrypto -lssl -o dbwhitelist
