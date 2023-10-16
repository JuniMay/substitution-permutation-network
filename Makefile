run:
	gcc -o main.exe src/main.c
	./main.exe

encryptor:
	gcc -o encryptor.exe src/encryptor.c

linear:
	gcc -o linear.exe src/linear.c
	./linear.exe