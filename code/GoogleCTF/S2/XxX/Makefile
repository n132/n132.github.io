all: exp

exp: exp.cc pwn.S
	gcc -no-pie -c ./pwn.S -o ./pwn.o
	g++ -no-pie -c ./exp.cc -o ./exp.o
	g++ --static -no-pie ./exp.o ./pwn.o -o ./exp

clean:
	rm -rf ./pwn.o ./exp.o ./exp