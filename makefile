

all:
	g++ -L./build -l:libcryptopp.a -I./vendor/cryptopp *.cpp -o main
