LABORATORIO 1 INF256 - 2025-1

dentro dee /src/ están las fuentes y programas compilados a correr en WSL u otro sistema basado en UNIX.
Todo se probó en Linux Fedora 42 y la WSL de windows 11. No nos hacemos cargo de diferencias en ejecución sobre otros sistemas operativos

dentro de /claves/ están las claves utilizadas para los cifrados asimétricos. Formato .pem en hexagecimal, y formato .der decimal.

la compilación se logra corriendo:

$ make

la ejecución con:

$ ./src/[nombre_del_ejecutable]
