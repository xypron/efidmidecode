dmidecode:
	gcc  dmidecode.c dmiopt.c dmioem.c dmioutput.c util.c -o dmidecode

clean:
	rm -f dmidecode
