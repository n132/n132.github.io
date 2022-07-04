all: exp

exp: exp.c X.s
	gcc -no-pie -c ./X.S -o ./X.o
	gcc -w -no-pie -c ./exp.c -o ./exp.o
	gcc --static -no-pie ./exp.o ./X.o -o exp
	echo "n132{test_flag}" > ./flag
clean:
	rm -rf ./X.o ./exp.o ./exp ./flag