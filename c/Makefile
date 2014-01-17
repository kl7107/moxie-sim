CFLAGS = -Wall -g

sim: sim.o xterm.o

nethack.js: sim.c
	$(CC) $(CFLAGS) -o $@ $< --pre-js termlib.js

