DATA = data/linear.txt
KEY = 00111010100101001101011000111111
SIZE = 8000

.PHONY: run encryptor linear clean

run:
	gcc -o main.exe src/main.c
	./main.exe

encryptor:
	gcc -o encryptor.exe src/encryptor.c

linear: encryptor
	gcc -o linear.exe src/linear.c
	python scripts/datagen.py $(KEY) $(SIZE) -o $(DATA)
	./linear.exe $(DATA)

clean:
	rm -f *.exe