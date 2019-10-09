simple:
	gcc -c *.c -O2 && gcc *.o -o main -lcrypto
	
clean:
	rm *.o main
