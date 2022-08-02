SRC_FILES = contained.c
CC_FLAGS = -Wall -Werror -lcap -lseccomp
CC = gcc

all:
	${CC} ${SRC_FILES} ${CC_FLAGS} -o contained

clean:
	rm -f contained
