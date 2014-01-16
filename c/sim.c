/* Simulator for the moxie processor
   Copyright (C) 2008-2013 Free Software Foundation, Inc.
   Contributed by Anthony Green
   Modified by Krister Lagerström

This file was copied from GDB, the GNU debugger.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

// XXX Load ELF
// XXX GDB. HW brkpts
// XXX 
// XXX Dynamic mem maps
// XXX Timers, etc
// XXX 
// XXX 
// XXX 
// XXX 
// XXX 
// XXX 

#define _XOPEN_SOURCE 
#define _BSD_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>
#include <termios.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libgen.h>
#include <poll.h>


typedef int word;
typedef unsigned int uword;


/*! Data structure to represent the connection to the xterm */
struct fd_channel
{
  int fdin;
  int fdout;
};

struct xterm_channel
{
  struct fd_channel fds;
  int pid;
  char **argv;
};

static FILE *tracefile = NULL;

static struct xterm_channel *xt_fd = NULL;

/* Forward declaration of static functions */
static void  xterm_close (void *data);
static void *xterm_init (const char *input);
static int   xterm_open (void *data);
static void  xterm_putc (char c);
static int xterm_getc (int peek);

#define MARIN_UART_BASE    0xF0000008
#define MARIN_UART_RXRDY   (MARIN_UART_BASE + 0)
#define MARIN_UART_TXRDY   (MARIN_UART_BASE + 2)
#define MARIN_UART_RXDATA  (MARIN_UART_BASE + 4)
#define MARIN_UART_TXDATA  (MARIN_UART_BASE + 6)

/* Extract the signed 10-bit offset from a 16-bit branch
   instruction.  */
#define INST2OFFSET(o) ((((signed short)((o & ((1<<10)-1))<<6))>>6)<<1)

#define EXTRACT_WORD(addr) rlat(0, addr)

uint8_t sim_core_read_aligned_1(addr)
{
  return 0;
}




/* moxie register names.  */
static const char *reg_names[16] = 
  { "$fp", "$sp", "$r0", "$r1", "$r2", "$r3", "$r4", "$r5", 
    "$r6", "$r7", "$r8", "$r9", "$r10", "$r11", "$r12", "$r13" };

/* The machine state.

   This state is maintained in host byte order.  The fetch/store
   register functions must translate between host byte order and the
   target processor byte order.  Keeping this data in target byte
   order simplifies the register read/write functions.  Keeping this
   data in native order improves the performance of the simulator.
   Simulation speed is deemed more important.  */

#define NUM_MOXIE_REGS 17 /* Including PC */
#define NUM_MOXIE_SREGS 256 /* The special registers */
#define PC_REGNO     16

/* The ordering of the moxie_regset structure is matched in the
   gdb/config/moxie/tm-moxie.h file in the REGISTER_NAMES macro.  */
struct moxie_regset
{
  word		  regs[NUM_MOXIE_REGS + 1]; /* primary registers */
  word		  sregs[256];             /* special registers */
  word            cc;                   /* the condition code reg */
  int		  exception;
  unsigned long long insts;                /* instruction counter */
};

#define CC_GT  1<<0
#define CC_LT  1<<1
#define CC_EQ  1<<2
#define CC_GTU 1<<3
#define CC_LTU 1<<4

union
{
  struct moxie_regset asregs;
  word asints [1];		/* but accessed larger... */
} cpu;


static void
set_initial_gprs ()
{
  int i;
  
  /* Set up machine just out of reset.  */
  cpu.asregs.regs[PC_REGNO] = 0;
  
  /* Clean out the register contents.  */
  for (i = 0; i < NUM_MOXIE_REGS; i++)
    cpu.asregs.regs[i] = 0;
  for (i = 0; i < NUM_MOXIE_SREGS; i++)
    cpu.asregs.sregs[i] = 0;
}

static void
interrupt ()
{
  cpu.asregs.exception = SIGINT;
}










#define RAM_LOW 0x30000000
#define RAM_SIZE 0x4000000
#define RAM_HIGH (RAM_LOW + RAM_SIZE - 1)

uint8_t mem[RAM_SIZE];


/* Write a 1 byte value to memory.  */

static void  
wbat (word pc, word x, word v)
{
  if (x >= RAM_LOW && x <= RAM_HIGH) {
    mem[x - RAM_LOW] = v;
  } else {
    printf("BAD write: PC=0x%08x, addr=0x%08x, val=0x%02x\n", pc, x, v);
  }
}

/* Write a 2 byte value to memory.  */

static void  
wsat (word pc, word x, word v)
{
  wbat(pc, x+0, (v>>8) & 0xff);
  wbat(pc, x+1, (v>>0) & 0xff);
}

/* Write a 4 byte value to memory.  */

static void  
wlat (word pc, word x, word v)
{
  wbat(pc, x+0, (v>>24) & 0xff);
  wbat(pc, x+1, (v>>16) & 0xff);
  wbat(pc, x+2, (v>>8) & 0xff);
  wbat(pc, x+3, (v>>0) & 0xff);
}

/* Read 1 byte from memory.  */
static int  
rbat (word pc, word x)
{
  if (x >= RAM_LOW && x <= RAM_HIGH) {
    return mem[x - RAM_LOW];
  } else {
    printf("BAD read: PC=0x%08x, addr=0x%08x\n", pc, x);
    return 0;
  }
}

/* Read 2 bytes from memory.  */
static int  
rsat (word pc, word x)
{
  word val;

  
  val = ((rbat(pc, x+0) << 8) | 
	 (rbat(pc, x+1) << 0));
  
  return val;
}

/* Read 4 bytes from memory.  */
static int  
rlat (word pc, word x)
{
  int val;

  
  val = ((rbat(pc, x+0) << 24) | 
	 (rbat(pc, x+1) << 16) |
	 (rbat(pc, x+2) <<  8) |
	 (rbat(pc, x+3) <<  0));
  
  return val;
}

















#define TRACE(str) if (tracing) fprintf(tracefile,"0x%08x, %s, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x\n", opc, str, cpu.asregs.regs[0], cpu.asregs.regs[1], cpu.asregs.regs[2], cpu.asregs.regs[3], cpu.asregs.regs[4], cpu.asregs.regs[5], cpu.asregs.regs[6], cpu.asregs.regs[7], cpu.asregs.regs[8], cpu.asregs.regs[9], cpu.asregs.regs[10], cpu.asregs.regs[11], cpu.asregs.regs[12], cpu.asregs.regs[13], cpu.asregs.regs[14], cpu.asregs.regs[15]);

static int tracing = 0;

void
sim_resume (int step)
{
  word pc, opc;
  unsigned long long insts;
  unsigned short inst;
  void (* sigsave)();


  sigsave = signal (SIGINT, interrupt);
  cpu.asregs.exception = step ? SIGTRAP: 0;
  pc = cpu.asregs.regs[PC_REGNO];
  insts = cpu.asregs.insts;

  /* Run instructions here. */
  do 
    {
      opc = pc;

      /* Fetch the instruction at pc.  */
      inst = rsat(pc, pc);

      /* Decode instruction.  */
      if (inst & (1 << 15))
	{
	  if (inst & (1 << 14))
	    {
	      /* This is a Form 3 instruction.  */
	      int opcode = (inst >> 10 & 0xf);

	      switch (opcode)
		{
		case 0x00: /* beq */
		  {
		    TRACE("beq");
		    if (cpu.asregs.cc & CC_EQ)
		      pc += INST2OFFSET(inst);
		  }
		  break;
		case 0x01: /* bne */
		  {
		    TRACE("bne");
		    if (! (cpu.asregs.cc & CC_EQ))
		      pc += INST2OFFSET(inst);
		  }
		  break;
		case 0x02: /* blt */
		  {
		    TRACE("blt");
		    if (cpu.asregs.cc & CC_LT)
		      pc += INST2OFFSET(inst);
		  }		  break;
		case 0x03: /* bgt */
		  {
		    TRACE("bgt");
		    if (cpu.asregs.cc & CC_GT)
		      pc += INST2OFFSET(inst);
		  }
		  break;
		case 0x04: /* bltu */
		  {
		    TRACE("bltu");
		    if (cpu.asregs.cc & CC_LTU)
		      pc += INST2OFFSET(inst);
		  }
		  break;
		case 0x05: /* bgtu */
		  {
		    TRACE("bgtu");
		    if (cpu.asregs.cc & CC_GTU)
		      pc += INST2OFFSET(inst);
		  }
		  break;
		case 0x06: /* bge */
		  {
		    TRACE("bge");
		    if (cpu.asregs.cc & (CC_GT | CC_EQ))
		      pc += INST2OFFSET(inst);
		  }
		  break;
		case 0x07: /* ble */
		  {
		    TRACE("ble");
		    if (cpu.asregs.cc & (CC_LT | CC_EQ))
		      pc += INST2OFFSET(inst);
		  }
		  break;
		case 0x08: /* bgeu */
		  {
		    TRACE("bgeu");
		    if (cpu.asregs.cc & (CC_GTU | CC_EQ))
		      pc += INST2OFFSET(inst);
		  }
		  break;
		case 0x09: /* bleu */
		  {
		    TRACE("bleu");
		    if (cpu.asregs.cc & (CC_LTU | CC_EQ))
		      pc += INST2OFFSET(inst);
		  }
		  break;
		default:
		  {
		    TRACE("SIGILL3");
		    cpu.asregs.exception = SIGILL;
		    break;
		  }
		}
	    }
	  else
	    {
	      /* This is a Form 2 instruction.  */
	      int opcode = (inst >> 12 & 0x3);
	      switch (opcode)
		{
		case 0x00: /* inc */
		  {
		    int a = (inst >> 8) & 0xf;
		    unsigned av = cpu.asregs.regs[a];
		    unsigned v = (inst & 0xff);
		    TRACE("inc");
		    cpu.asregs.regs[a] = av + v;
		  }
		  break;
		case 0x01: /* dec */
		  {
		    int a = (inst >> 8) & 0xf;
		    unsigned av = cpu.asregs.regs[a];
		    unsigned v = (inst & 0xff);
		    TRACE("dec");
		    cpu.asregs.regs[a] = av - v;
		  }
		  break;
		case 0x02: /* gsr */
		  {
		    int a = (inst >> 8) & 0xf;
		    unsigned v = (inst & 0xff);
		    TRACE("gsr");
		    cpu.asregs.regs[a] = cpu.asregs.sregs[v];
		  }
		  break;
		case 0x03: /* ssr */
		  {
		    int a = (inst >> 8) & 0xf;
		    unsigned v = (inst & 0xff);
		    TRACE("ssr");
		    cpu.asregs.sregs[v] = cpu.asregs.regs[a];
		  }
		  break;
		default:
		  TRACE("SIGILL2");
		  cpu.asregs.exception = SIGILL;
		  break;
		}
	    }
	}
      else
	{
	  /* This is a Form 1 instruction.  */
	  int opcode = inst >> 8;
	  switch (opcode)
	    {
	    case 0x00: /* bad */
	      opc = opcode;
	      TRACE("SIGILL0");
	      cpu.asregs.exception = SIGILL;
	      break;
	    case 0x01: /* ldi.l (immediate) */
	      {
		int reg = (inst >> 4) & 0xf;
		TRACE("ldi.l");
		unsigned int val = EXTRACT_WORD(pc+2);
		cpu.asregs.regs[reg] = val;
		pc += 4;
	      }
	      break;
	    case 0x02: /* mov (register-to-register) */
	      {
		int dest  = (inst >> 4) & 0xf;
		int src = (inst ) & 0xf;
		TRACE("mov");
		cpu.asregs.regs[dest] = cpu.asregs.regs[src];
	      }
	      break;
 	    case 0x03: /* jsra */
 	      {
 		unsigned int fn = EXTRACT_WORD(pc+2);
 		unsigned int sp = cpu.asregs.regs[1];
		TRACE("jsra");
 		/* Save a slot for the static chain.  */
		sp -= 4;

 		/* Push the return address.  */
		sp -= 4;
 		wlat (opc, sp, pc + 6);
 		
 		/* Push the current frame pointer.  */
 		sp -= 4;
 		wlat (opc, sp, cpu.asregs.regs[0]);
 
 		/* Uncache the stack pointer and set the pc and $fp.  */
		cpu.asregs.regs[1] = sp;
		cpu.asregs.regs[0] = sp;
 		pc = fn - 2;
 	      }
 	      break;
 	    case 0x04: /* ret */
 	      {
 		unsigned int sp = cpu.asregs.regs[0];

		TRACE("ret");
 
 		/* Pop the frame pointer.  */
 		cpu.asregs.regs[0] = rlat (opc, sp);
 		sp += 4;
 		
 		/* Pop the return address.  */
 		pc = rlat (opc, sp) - 2;
 		sp += 4;

		/* Skip over the static chain slot.  */
		sp += 4;
 
 		/* Uncache the stack pointer.  */
 		cpu.asregs.regs[1] = sp;
  	      }
  	      break;
	    case 0x05: /* add.l */
	      {
		int a = (inst >> 4) & 0xf;
		int b = inst & 0xf;
		unsigned av = cpu.asregs.regs[a];
		unsigned bv = cpu.asregs.regs[b];
		TRACE("add.l");
		cpu.asregs.regs[a] = av + bv;
	      }
	      break;
	    case 0x06: /* push */
	      {
		int a = (inst >> 4) & 0xf;
		int b = inst & 0xf;
		int sp = cpu.asregs.regs[a] - 4;
		TRACE("push");
		wlat (opc, sp, cpu.asregs.regs[b]);
		cpu.asregs.regs[a] = sp;
	      }
	      break;
	    case 0x07: /* pop */
	      {
		int a = (inst >> 4) & 0xf;
		int b = inst & 0xf;
		int sp = cpu.asregs.regs[a];
		TRACE("pop");
		cpu.asregs.regs[b] = rlat (opc, sp);
		cpu.asregs.regs[a] = sp + 4;
	      }
	      break;
	    case 0x08: /* lda.l */
	      {
		int reg = (inst >> 4) & 0xf;
		unsigned int addr = EXTRACT_WORD(pc+2);
		TRACE("lda.l");
		cpu.asregs.regs[reg] = rlat (opc, addr);
		pc += 4;
	      }
	      break;
	    case 0x09: /* sta.l */
	      {
		int reg = (inst >> 4) & 0xf;
		unsigned int addr = EXTRACT_WORD(pc+2);
		TRACE("sta.l");
		wlat (opc, addr, cpu.asregs.regs[reg]);
		pc += 4;
	      }
	      break;
	    case 0x0a: /* ld.l (register indirect) */
	      {
		int src  = inst & 0xf;
		int dest = (inst >> 4) & 0xf;
		int xv;
		TRACE("ld.l");
		xv = cpu.asregs.regs[src];
		cpu.asregs.regs[dest] = rlat (opc, xv);
	      }
	      break;
	    case 0x0b: /* st.l */
	      {
		int dest = (inst >> 4) & 0xf;
		int val  = inst & 0xf;
		TRACE("st.l");
		wlat (opc, cpu.asregs.regs[dest], cpu.asregs.regs[val]);
	      }
	      break;
	    case 0x0c: /* ldo.l */
	      {
		unsigned int addr = EXTRACT_WORD(pc+2);
		int a = (inst >> 4) & 0xf;
		int b = inst & 0xf;
		TRACE("ldo.l");
		addr += cpu.asregs.regs[b];
		cpu.asregs.regs[a] = rlat (opc, addr);
		pc += 4;
	      }
	      break;
	    case 0x0d: /* sto.l */
	      {
		unsigned int addr = EXTRACT_WORD(pc+2);
		int a = (inst >> 4) & 0xf;
		int b = inst & 0xf;
		TRACE("sto.l");
		addr += cpu.asregs.regs[a];
		wlat (opc, addr, cpu.asregs.regs[b]);
		pc += 4;
	      }
	      break;
	    case 0x0e: /* cmp */
	      {
		int a  = (inst >> 4) & 0xf;
		int b  = inst & 0xf;
		int cc = 0;
		int va = cpu.asregs.regs[a];
		int vb = cpu.asregs.regs[b]; 

		TRACE("cmp");

		if (va == vb)
		  cc = CC_EQ;
		else
		  {
		    cc |= (va < vb ? CC_LT : 0);
		    cc |= (va > vb ? CC_GT : 0);
		    cc |= ((unsigned int) va < (unsigned int) vb ? CC_LTU : 0);
		    cc |= ((unsigned int) va > (unsigned int) vb ? CC_GTU : 0);
		  }

		cpu.asregs.cc = cc;
	      }
	      break;
	    case 0x0f: /* nop */
	      break;
	    case 0x10: /* bad */
	    case 0x11: /* bad */
	    case 0x12: /* bad */
	    case 0x13: /* bad */
	    case 0x14: /* bad */
	    case 0x15: /* bad */
	    case 0x16: /* bad */
	    case 0x17: /* bad */
	    case 0x18: /* bad */
	      {
		opc = opcode;
		TRACE("SIGILL0");
		cpu.asregs.exception = SIGILL;
		break;
	      }
	    case 0x19: /* jsr */
	      {
		unsigned int fn = cpu.asregs.regs[(inst >> 4) & 0xf];
		unsigned int sp = cpu.asregs.regs[1];

		TRACE("jsr");

 		/* Save a slot for the static chain.  */
		sp -= 4;

		/* Push the return address.  */
		sp -= 4;
		wlat (opc, sp, pc + 2);
		
		/* Push the current frame pointer.  */
		sp -= 4;
		wlat (opc, sp, cpu.asregs.regs[0]);

		/* Uncache the stack pointer and set the fp & pc.  */
		cpu.asregs.regs[1] = sp;
		cpu.asregs.regs[0] = sp;
		pc = fn - 2;
	      }
	      break;
	    case 0x1a: /* jmpa */
	      {
		unsigned int tgt = EXTRACT_WORD(pc+2);
		TRACE("jmpa");
		pc = tgt - 2;
	      }
	      break;
	    case 0x1b: /* ldi.b (immediate) */
	      {
		int reg = (inst >> 4) & 0xf;

		unsigned int val = EXTRACT_WORD(pc+2);
		TRACE("ldi.b");
		cpu.asregs.regs[reg] = val;
		pc += 4;
	      }
	      break;
	    case 0x1c: /* ld.b (register indirect) */
	      {
		int src  = inst & 0xf;
		int dest = (inst >> 4) & 0xf;
		int xv;
		TRACE("ld.b");
		xv = cpu.asregs.regs[src];
		cpu.asregs.regs[dest] = rbat (opc, xv);
	      }
	      break;
	    case 0x1d: /* lda.b */
	      {
		int reg = (inst >> 4) & 0xf;
		unsigned int addr = EXTRACT_WORD(pc+2);
		TRACE("lda.b");
		cpu.asregs.regs[reg] = rbat (opc, addr);
		pc += 4;
	      }
	      break;
	    case 0x1e: /* st.b */
	      {
		int dest = (inst >> 4) & 0xf;
		int val  = inst & 0xf;
		TRACE("st.b");
		wbat (opc, cpu.asregs.regs[dest], cpu.asregs.regs[val]);
	      }
	      break;
	    case 0x1f: /* sta.b */
	      {
		int reg = (inst >> 4) & 0xf;
		unsigned int addr = EXTRACT_WORD(pc+2);
		TRACE("sta.b");
		wbat (opc, addr, cpu.asregs.regs[reg]);
		pc += 4;
	      }
	      break;
	    case 0x20: /* ldi.s (immediate) */
	      {
		int reg = (inst >> 4) & 0xf;

		unsigned int val = EXTRACT_WORD(pc+2);
		TRACE("ldi.s");
		cpu.asregs.regs[reg] = val;
		pc += 4;
	      }
	      break;
	    case 0x21: /* ld.s (register indirect) */
	      {
		int src  = inst & 0xf;
		int dest = (inst >> 4) & 0xf;
		int xv;
		TRACE("ld.s");
		xv = cpu.asregs.regs[src];
		switch (xv) {
		case MARIN_UART_RXRDY:
		  cpu.asregs.regs[dest] = xterm_getc(1) == -1 ? 0 : 1;
		  break;
		case MARIN_UART_RXDATA:
		{
		  int ch = xterm_getc(0);
		  cpu.asregs.regs[dest] = ch == -1 ? 0 : ch;
		  break;
		}
		case MARIN_UART_TXRDY:
		  cpu.asregs.regs[dest] = 1; // XXX always ready
		  break;
		default:
		  cpu.asregs.regs[dest] = rsat (opc, xv);
		}
	      }
	      break;
	    case 0x22: /* lda.s */
	      {
		int reg = (inst >> 4) & 0xf;
		unsigned int addr = EXTRACT_WORD(pc+2);
		TRACE("lda.s");
		cpu.asregs.regs[reg] = rsat (opc, addr);
		pc += 4;
	      }
	      break;
	    case 0x23: /* st.s */
	      {
		int dest = (inst >> 4) & 0xf;
		int val  = inst & 0xf;
		TRACE("st.s");
		switch (cpu.asregs.regs[dest]) {
		case MARIN_UART_TXDATA:
		  //printf("Console output  %d'\n", 
		  //	 cpu.asregs.regs[val]);
		  xterm_putc(cpu.asregs.regs[val]);
		  break;
		default:
		  wsat (opc, cpu.asregs.regs[dest], cpu.asregs.regs[val]);
		}
	      }
	      break;
	    case 0x24: /* sta.s */
	      {
		int reg = (inst >> 4) & 0xf;
		unsigned int addr = EXTRACT_WORD(pc+2);
		TRACE("sta.s");
		wsat (opc, addr, cpu.asregs.regs[reg]);
		pc += 4;
	      }
	      break;
	    case 0x25: /* jmp */
	      {
		int reg = (inst >> 4) & 0xf;
		TRACE("jmp");
		pc = cpu.asregs.regs[reg] - 2;
	      }
	      break;
	    case 0x26: /* and */
	      {
		int a = (inst >> 4) & 0xf;
		int b = inst & 0xf;
		int av, bv;
		TRACE("and");
		av = cpu.asregs.regs[a];
		bv = cpu.asregs.regs[b];
		cpu.asregs.regs[a] = av & bv;
	      }
	      break;
	    case 0x27: /* lshr */
	      {
		int a = (inst >> 4) & 0xf;
		int b = inst & 0xf;
		int av = cpu.asregs.regs[a];
		int bv = cpu.asregs.regs[b];
		TRACE("lshr");
		cpu.asregs.regs[a] = (unsigned) ((unsigned) av >> bv);
	      }
	      break;
	    case 0x28: /* ashl */
	      {
		int a = (inst >> 4) & 0xf;
		int b = inst & 0xf;
		int av = cpu.asregs.regs[a];
		int bv = cpu.asregs.regs[b];
		TRACE("ashl");
		cpu.asregs.regs[a] = av << bv;
	      }
	      break;
	    case 0x29: /* sub.l */
	      {
		int a = (inst >> 4) & 0xf;
		int b = inst & 0xf;
		unsigned av = cpu.asregs.regs[a];
		unsigned bv = cpu.asregs.regs[b];
		TRACE("sub.l");
		cpu.asregs.regs[a] = av - bv;
	      }
	      break;
	    case 0x2a: /* neg */
	      {
		int a  = (inst >> 4) & 0xf;
		int b  = inst & 0xf;
		int bv = cpu.asregs.regs[b];
		TRACE("neg");
		cpu.asregs.regs[a] = - bv;
	      }
	      break;
	    case 0x2b: /* or */
	      {
		int a = (inst >> 4) & 0xf;
		int b = inst & 0xf;
		int av, bv;
		TRACE("or");
		av = cpu.asregs.regs[a];
		bv = cpu.asregs.regs[b];
		cpu.asregs.regs[a] = av | bv;
	      }
	      break;
	    case 0x2c: /* not */
	      {
		int a = (inst >> 4) & 0xf;
		int b = inst & 0xf;
		int bv = cpu.asregs.regs[b];
		TRACE("not");
		cpu.asregs.regs[a] = 0xffffffff ^ bv;
	      }
	      break;
	    case 0x2d: /* ashr */
	      {
		int a  = (inst >> 4) & 0xf;
		int b  = inst & 0xf;
		int av = cpu.asregs.regs[a];
		int bv = cpu.asregs.regs[b];
		TRACE("ashr");
		cpu.asregs.regs[a] = av >> bv;
	      }
	      break;
	    case 0x2e: /* xor */
	      {
		int a = (inst >> 4) & 0xf;
		int b = inst & 0xf;
		int av, bv;
		TRACE("xor");
		av = cpu.asregs.regs[a];
		bv = cpu.asregs.regs[b];
		cpu.asregs.regs[a] = av ^ bv;
	      }
	      break;
	    case 0x2f: /* mul.l */
	      {
		int a = (inst >> 4) & 0xf;
		int b = inst & 0xf;
		unsigned av = cpu.asregs.regs[a];
		unsigned bv = cpu.asregs.regs[b];
		TRACE("mul.l");
		cpu.asregs.regs[a] = av * bv;
	      }
	      break;
	    case 0x30: /* swi */
	      {
		unsigned int inum = EXTRACT_WORD(pc+2);
		TRACE("swi");
		/* Set the special registers appropriately.  */
		cpu.asregs.sregs[2] = 3; /* MOXIE_EX_SWI */
	        cpu.asregs.sregs[3] = inum;




		// XXX Implement





		pc += 4;
	      }
	      break;
	    case 0x31: /* div.l */
	      {
		int a = (inst >> 4) & 0xf;
		int b = inst & 0xf;
		int av = cpu.asregs.regs[a];
		int bv = cpu.asregs.regs[b];
		TRACE("div.l");
		cpu.asregs.regs[a] = av / bv;
	      }
	      break;
	    case 0x32: /* udiv.l */
	      {
		int a = (inst >> 4) & 0xf;
		int b = inst & 0xf;
		unsigned int av = cpu.asregs.regs[a];
		unsigned int bv = cpu.asregs.regs[b];
		TRACE("udiv.l");
		cpu.asregs.regs[a] = (av / bv);
	      }
	      break;
	    case 0x33: /* mod.l */
	      {
		int a = (inst >> 4) & 0xf;
		int b = inst & 0xf;
		int av = cpu.asregs.regs[a];
		int bv = cpu.asregs.regs[b];
		TRACE("mod.l");
		cpu.asregs.regs[a] = av % bv;
	      }
	      break;
	    case 0x34: /* umod.l */
	      {
		int a = (inst >> 4) & 0xf;
		int b = inst & 0xf;
		unsigned int av = cpu.asregs.regs[a];
		unsigned int bv = cpu.asregs.regs[b];
		TRACE("umod.l");
		cpu.asregs.regs[a] = (av % bv);
	      }
	      break;
	    case 0x35: /* brk */
	      TRACE("brk");
	      cpu.asregs.exception = SIGTRAP;
	      pc -= 2; /* Adjust pc */
	      break;
	    case 0x36: /* ldo.b */
	      {
		unsigned int addr = EXTRACT_WORD(pc+2);
		int a = (inst >> 4) & 0xf;
		int b = inst & 0xf;
		TRACE("ldo.b");
		addr += cpu.asregs.regs[b];
		cpu.asregs.regs[a] = rbat (opc, addr);
		pc += 4;
	      }
	      break;
	    case 0x37: /* sto.b */
	      {
		unsigned int addr = EXTRACT_WORD(pc+2);
		int a = (inst >> 4) & 0xf;
		int b = inst & 0xf;
		TRACE("sto.b");
		addr += cpu.asregs.regs[a];
		wbat (opc, addr, cpu.asregs.regs[b]);
		pc += 4;
	      }
	      break;
	    case 0x38: /* ldo.s */
	      {
		unsigned int addr = EXTRACT_WORD(pc+2);
		int a = (inst >> 4) & 0xf;
		int b = inst & 0xf;
		TRACE("ldo.s");
		addr += cpu.asregs.regs[b];
		cpu.asregs.regs[a] = rsat (opc, addr);
		pc += 4;
	      }
	      break;
	    case 0x39: /* sto.s */
	      {
		unsigned int addr = EXTRACT_WORD(pc+2);
		int a = (inst >> 4) & 0xf;
		int b = inst & 0xf;
		TRACE("sto.s");
		addr += cpu.asregs.regs[a];
		wsat (opc, addr, cpu.asregs.regs[b]);
		pc += 4;
	      }
	      break;
	    default:
	      opc = opcode;
	      TRACE("SIGILL1");
	      cpu.asregs.exception = SIGILL;
	      break;
	    }
	}

      insts++;
      pc += 2;

    } while (!cpu.asregs.exception);

  /* Hide away the things we've cached while executing.  */
  cpu.asregs.regs[PC_REGNO] = pc;
  cpu.asregs.insts += insts;		/* instructions done ... */

  signal (SIGINT, sigsave);
}


int main(int ac, char *av[])
{
  int fd, val;


  set_initial_gprs ();	/* Reset the GPR registers.  */
  
  cpu.asregs.regs[PC_REGNO] = 0x30000000;

  fd = open(av[1], O_RDONLY);
  
  printf("fd = %d\n", fd);

  val = read(fd, mem, RAM_SIZE);

  printf("Read %d bytes from '%s'\n", val, av[1]);

  sim_resume(0);

  return 0;
}



int
sim_trace (void)
{
  if (tracefile == 0)
    tracefile = fopen("trace.csv", "wb");

  tracing = 1;
  
  sim_resume (0);

  tracing = 0;
  
  return 1;
}


int
sim_stop (void)
{
  cpu.asregs.exception = SIGINT;
  return 1;
}




static void
xterm_close (void *data)
{
  struct xterm_channel *xt = data;

  if (!xt)
    return;

  if (xt->fds.fdin != -1)
    close (xt->fds.fdin);

  if (xt->pid != -1)
    {
      kill (xt->pid, SIGKILL);
      waitpid (xt->pid, NULL, 0);
    }

  if (xt->argv)
    free (xt->argv);

  xt->fds.fdin = -1;
  xt->fds.fdout = -1;
  xt->pid = -1;
  xt->argv = NULL;

}

static void
xterm_exit (int i, void *data)
{
  xterm_close (data);
}

#define MAX_XTERM_ARGS 100
static void *
xterm_init (const char *input)
{
  struct xterm_channel *retval = malloc (sizeof (struct xterm_channel));

  if (retval)
    {
      int i;
      char *arglist;

      retval->fds.fdin = -1;
      retval->fds.fdout = -1;
      retval->pid = -1;

      /* reset cause exit(1), leaving an xterm opened */
      on_exit (xterm_exit, retval);

      i = 2;
      arglist = (char *) input;
      retval->argv = malloc (sizeof (char *) * MAX_XTERM_ARGS);
      if (!retval->argv)
	{
	  free (retval);
	  return NULL;
	}
      /* Assume xterm arguments are separated by whitespace */
      while ((retval->argv[i++] = strtok (arglist, " \t\n")))
	{
	  arglist = NULL;
	  if (i == MAX_XTERM_ARGS - 1)
	    {
	      free (retval);
	      return NULL;
	    }
	}

    }
  return (void *) retval;
}



static int
xterm_open (void *data)
{
  struct xterm_channel *xt = data;
  int master, retval;
  char *slavename;
  struct termios termio;
  char arg[64], *fin;

  if (!data)
    {
      errno = ENODEV;
      return -1;
    }

  master = open ("/dev/ptmx", O_RDWR);

  if (master < 0)
    return -1;

  grantpt (master);
  unlockpt (master);
  slavename = (char *) ptsname (master);

  if (!slavename)
    {
      errno = ENOTTY;
      goto closemastererror;
    }

  xt->fds.fdout = xt->fds.fdin = open (slavename, O_RDWR);
  if (xt->fds.fdout < 0)
    goto closemastererror;

  retval = tcgetattr (xt->fds.fdin, &termio);
  if (retval < 0)
    goto closeslaveerror;

  cfmakeraw (&termio);
  retval = tcsetattr (xt->fds.fdin, TCSADRAIN, &termio);
  if (retval < 0)
    goto closeslaveerror;

  xt->pid = fork ();

  if (xt->pid == -1)
    goto closeslaveerror;

  if (xt->pid == 0)
    {
      /* Ctrl-C on sim still kill the xterm, grrr */
      signal (SIGINT, SIG_IGN);

      fin = slavename + strlen (slavename) - 2;
      if (strchr (fin, '/'))
	{
	  sprintf (arg, "-S%s/%d", basename (slavename), master);
	}
      else
	{
	  sprintf (arg, "-S%c%c%d", fin[0], fin[1], master);
	}
      xt->argv[0] = "xterm";
      xt->argv[1] = arg;
      execvp ("xterm", xt->argv);
      if (write (master, "\n", 1) < 0)	/* Don't ignore result */
	{
	  printf ("ERROR: xterm: write failed\n");
	}
      exit (1);
    }

  do {
    retval = read (xt->fds.fdin, &arg, 1);
    printf("Xterm initial read = %c\n", arg[0]);
  } while (retval >= 0 && arg[0] != '\n');
  if (retval < 0)
    goto closeslaveerror;

  cfmakeraw (&termio);
  retval = tcsetattr (xt->fds.fdin, TCSADRAIN, &termio);

  if (retval < 0)
    goto closeslaveerror;

  return 0;

closeslaveerror:
  close (xt->fds.fdin);

closemastererror:
  close (master);
  xt->pid = xt->fds.fdin = xt->fds.fdout = -1;
  return -1;

}


int swrite( int fd, const char *str, ssize_t len )
{
  ssize_t total_bytes_written = 0;
  ssize_t bytes_to_write = ( len >= 0 ) ? len : strlen( str );


  while ( total_bytes_written < bytes_to_write ) {
    ssize_t bytes_written = write( fd, str + total_bytes_written,
				   bytes_to_write - total_bytes_written );
    if ( bytes_written <= 0 ) {
      perror( "write" );
      return -1;
    } else {
      total_bytes_written += bytes_written;
    }
  }

  return 0;
}


static void xterm_putc (char c)
{
  if (!xt_fd) {
    xt_fd = xterm_init("");
  
    if (xterm_open(xt_fd) == -1) {
      printf("Failed to open xterm\n");
      exit(1);
    }
  }

  write(xt_fd->fds.fdout, &c, 1);

}

static int xterm_getc (int peek)
{
  if (!xt_fd) {
    xt_fd = xterm_init("");
  
    if (xterm_open(xt_fd) == -1) {
      printf("Failed to open xterm\n");
      exit(1);
    }
  }
  
  struct pollfd pollfds[1];

  pollfds[0].fd = xt_fd->fds.fdin;
  pollfds[0].events = POLLIN;

  int active_fds = poll(pollfds, 1, 0);
  if ( active_fds < 0 ) {
    perror( "poll" );
    exit(1);
  }

  if (active_fds  == 0) {
    return -1;
  }
    
  printf("got xterm rx\n");

  if (pollfds[0].revents & POLLIN) {
    if (!peek) {
      char c;

      ssize_t bytes_read = read(pollfds[0].fd, &c, 1);
      if (bytes_read == 0) { /* EOF */
	printf("xterm read error\n");
	exit(1);
      } else if (bytes_read < 0) {
	perror( "read" );
	printf("xterm read error\n");
	exit(1);
      }
      return c;
    } else {
      return 0;
    }    
  } else if ((pollfds[0].revents)
	     & (POLLERR | POLLHUP | POLLNVAL) ) {
    printf("xterm poll error\n");
    exit(1);
  }

  return -1;
}

