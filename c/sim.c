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

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <inttypes.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#ifndef EMSCRIPTEN

// Xterm-based console output
#include "xterm.h"
#define SIM_TERM_GETC(peek) xterm_getc(peek)
#define SIM_TERM_PUTC(c) xterm_putc(c)

#else

#include <emscripten.h>

#include "app.h"

// Console output to a Javascript VT100 emulator in the browser window
#define SIM_TERM_GETC(peek) term_read(peek)
#define SIM_TERM_PUTC(c) term_write(c) //printf("TERM char = %d\n", c);

int
term_read(int peek)
{
  int val;


  val = EM_ASM_INT({x = moxie_gui.uart.ReadChar(); return x;}, 0);

  if (!peek && val) {
    EM_ASM({moxie_gui.uart.ClearChar();});
  }

  if (val == 0) val = -1;

  if (val != -1 && !peek) {
    //printf("RX: %d\n", val);
  }

  return val;
}

void
term_write(int c)
{
#if 0
  EM_ASM_INT(term.write($0);
       ::"r"(c));
#endif
  EM_ASM_INT({moxie_gui.term.PutChar($0)}, c);
  //printf("TX: %d\n", c);
}

#endif


typedef int word;
typedef unsigned int uword;

#define RAM_LOW 0x30000000
#define RAM_SIZE 64*1024*1024
#define RAM_HIGH (RAM_LOW + RAM_SIZE - 1)

uint8_t mem[RAM_SIZE];


static FILE *tracefile = NULL;

/* Forward declaration of static functions */

#define MARIN_UART_BASE    0xF0000008
#define MARIN_UART_RXRDY   (MARIN_UART_BASE + 0)
#define MARIN_UART_TXRDY   (MARIN_UART_BASE + 2)
#define MARIN_UART_RXDATA  (MARIN_UART_BASE + 4)
#define MARIN_UART_TXDATA  (MARIN_UART_BASE + 6)

/* Extract the signed 10-bit offset from a 16-bit branch
   instruction.  */
#define INST2OFFSET(o) ((((signed short)((o & ((1<<10)-1))<<6))>>6)<<1)

#define EXTRACT_WORD(addr) rlat(0, addr)

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
} cpu;

#define CC_GT  1<<0
#define CC_LT  1<<1
#define CC_EQ  1<<2
#define CC_GTU 1<<3
#define CC_LTU 1<<4


static void
set_initial_gprs ()
{
  int i;
  
  /* Set up machine just out of reset.  */
  cpu.regs[PC_REGNO] = 0;
  
  /* Clean out the register contents.  */
  for (i = 0; i < NUM_MOXIE_REGS; i++)
    cpu.regs[i] = 0;
  for (i = 0; i < NUM_MOXIE_SREGS; i++)
    cpu.sregs[i] = 0;
}

static void
interrupt ()
{
  cpu.exception = SIGINT;
}


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



#define TRACE(str) if (tracing) fprintf(tracefile,"0x%08x, %s, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x\n", opc, str, cpu.regs[0], cpu.regs[1], cpu.regs[2], cpu.regs[3], cpu.regs[4], cpu.regs[5], cpu.regs[6], cpu.regs[7], cpu.regs[8], cpu.regs[9], cpu.regs[10], cpu.regs[11], cpu.regs[12], cpu.regs[13], cpu.regs[14], cpu.regs[15]);

static int tracing = 0;

void
sim_resume (int step, int maxinsns)
{
  word pc, opc;
  unsigned long long insts;
  unsigned short inst;
  void (* sigsave)();


  sigsave = signal (SIGINT, interrupt);
  cpu.exception = step ? SIGTRAP: 0;
  pc = cpu.regs[PC_REGNO];
  insts = cpu.insts;

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
		    if (cpu.cc & CC_EQ)
		      pc += INST2OFFSET(inst);
		  }
		  break;
		case 0x01: /* bne */
		  {
		    TRACE("bne");
		    if (! (cpu.cc & CC_EQ))
		      pc += INST2OFFSET(inst);
		  }
		  break;
		case 0x02: /* blt */
		  {
		    TRACE("blt");
		    if (cpu.cc & CC_LT)
		      pc += INST2OFFSET(inst);
		  }		  break;
		case 0x03: /* bgt */
		  {
		    TRACE("bgt");
		    if (cpu.cc & CC_GT)
		      pc += INST2OFFSET(inst);
		  }
		  break;
		case 0x04: /* bltu */
		  {
		    TRACE("bltu");
		    if (cpu.cc & CC_LTU)
		      pc += INST2OFFSET(inst);
		  }
		  break;
		case 0x05: /* bgtu */
		  {
		    TRACE("bgtu");
		    if (cpu.cc & CC_GTU)
		      pc += INST2OFFSET(inst);
		  }
		  break;
		case 0x06: /* bge */
		  {
		    TRACE("bge");
		    if (cpu.cc & (CC_GT | CC_EQ))
		      pc += INST2OFFSET(inst);
		  }
		  break;
		case 0x07: /* ble */
		  {
		    TRACE("ble");
		    if (cpu.cc & (CC_LT | CC_EQ))
		      pc += INST2OFFSET(inst);
		  }
		  break;
		case 0x08: /* bgeu */
		  {
		    TRACE("bgeu");
		    if (cpu.cc & (CC_GTU | CC_EQ))
		      pc += INST2OFFSET(inst);
		  }
		  break;
		case 0x09: /* bleu */
		  {
		    TRACE("bleu");
		    if (cpu.cc & (CC_LTU | CC_EQ))
		      pc += INST2OFFSET(inst);
		  }
		  break;
		default:
		  {
		    TRACE("SIGILL3");
		    cpu.exception = SIGILL;
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
		    unsigned av = cpu.regs[a];
		    unsigned v = (inst & 0xff);
		    TRACE("inc");
		    cpu.regs[a] = av + v;
		  }
		  break;
		case 0x01: /* dec */
		  {
		    int a = (inst >> 8) & 0xf;
		    unsigned av = cpu.regs[a];
		    unsigned v = (inst & 0xff);
		    TRACE("dec");
		    cpu.regs[a] = av - v;
		  }
		  break;
		case 0x02: /* gsr */
		  {
		    int a = (inst >> 8) & 0xf;
		    unsigned v = (inst & 0xff);
		    TRACE("gsr");
		    cpu.regs[a] = cpu.sregs[v];
		  }
		  break;
		case 0x03: /* ssr */
		  {
		    int a = (inst >> 8) & 0xf;
		    unsigned v = (inst & 0xff);
		    TRACE("ssr");
		    cpu.sregs[v] = cpu.regs[a];
		  }
		  break;
		default:
		  TRACE("SIGILL2");
		  cpu.exception = SIGILL;
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
	      cpu.exception = SIGILL;
	      break;
	    case 0x01: /* ldi.l (immediate) */
	      {
		int reg = (inst >> 4) & 0xf;
		TRACE("ldi.l");
		unsigned int val = EXTRACT_WORD(pc+2);
		cpu.regs[reg] = val;
		pc += 4;
	      }
	      break;
	    case 0x02: /* mov (register-to-register) */
	      {
		int dest  = (inst >> 4) & 0xf;
		int src = (inst ) & 0xf;
		TRACE("mov");
		cpu.regs[dest] = cpu.regs[src];
	      }
	      break;
 	    case 0x03: /* jsra */
 	      {
 		unsigned int fn = EXTRACT_WORD(pc+2);
 		unsigned int sp = cpu.regs[1];
		TRACE("jsra");
 		/* Save a slot for the static chain.  */
		sp -= 4;

 		/* Push the return address.  */
		sp -= 4;
 		wlat (opc, sp, pc + 6);
 		
 		/* Push the current frame pointer.  */
 		sp -= 4;
 		wlat (opc, sp, cpu.regs[0]);
 
 		/* Uncache the stack pointer and set the pc and $fp.  */
		cpu.regs[1] = sp;
		cpu.regs[0] = sp;
 		pc = fn - 2;
 	      }
 	      break;
 	    case 0x04: /* ret */
 	      {
 		unsigned int sp = cpu.regs[0];

		TRACE("ret");
 
 		/* Pop the frame pointer.  */
 		cpu.regs[0] = rlat (opc, sp);
 		sp += 4;
 		
 		/* Pop the return address.  */
 		pc = rlat (opc, sp) - 2;
 		sp += 4;

		/* Skip over the static chain slot.  */
		sp += 4;
 
 		/* Uncache the stack pointer.  */
 		cpu.regs[1] = sp;
  	      }
  	      break;
	    case 0x05: /* add.l */
	      {
		int a = (inst >> 4) & 0xf;
		int b = inst & 0xf;
		unsigned av = cpu.regs[a];
		unsigned bv = cpu.regs[b];
		TRACE("add.l");
		cpu.regs[a] = av + bv;
	      }
	      break;
	    case 0x06: /* push */
	      {
		int a = (inst >> 4) & 0xf;
		int b = inst & 0xf;
		int sp = cpu.regs[a] - 4;
		TRACE("push");
		wlat (opc, sp, cpu.regs[b]);
		cpu.regs[a] = sp;
	      }
	      break;
	    case 0x07: /* pop */
	      {
		int a = (inst >> 4) & 0xf;
		int b = inst & 0xf;
		int sp = cpu.regs[a];
		TRACE("pop");
		cpu.regs[b] = rlat (opc, sp);
		cpu.regs[a] = sp + 4;
	      }
	      break;
	    case 0x08: /* lda.l */
	      {
		int reg = (inst >> 4) & 0xf;
		unsigned int addr = EXTRACT_WORD(pc+2);
		TRACE("lda.l");
		cpu.regs[reg] = rlat (opc, addr);
		pc += 4;
	      }
	      break;
	    case 0x09: /* sta.l */
	      {
		int reg = (inst >> 4) & 0xf;
		unsigned int addr = EXTRACT_WORD(pc+2);
		TRACE("sta.l");
		wlat (opc, addr, cpu.regs[reg]);
		pc += 4;
	      }
	      break;
	    case 0x0a: /* ld.l (register indirect) */
	      {
		int src  = inst & 0xf;
		int dest = (inst >> 4) & 0xf;
		int xv;
		TRACE("ld.l");
		xv = cpu.regs[src];
		cpu.regs[dest] = rlat (opc, xv);
	      }
	      break;
	    case 0x0b: /* st.l */
	      {
		int dest = (inst >> 4) & 0xf;
		int val  = inst & 0xf;
		TRACE("st.l");
		wlat (opc, cpu.regs[dest], cpu.regs[val]);
	      }
	      break;
	    case 0x0c: /* ldo.l */
	      {
		unsigned int addr = EXTRACT_WORD(pc+2);
		int a = (inst >> 4) & 0xf;
		int b = inst & 0xf;
		TRACE("ldo.l");
		addr += cpu.regs[b];
		cpu.regs[a] = rlat (opc, addr);
		pc += 4;
	      }
	      break;
	    case 0x0d: /* sto.l */
	      {
		unsigned int addr = EXTRACT_WORD(pc+2);
		int a = (inst >> 4) & 0xf;
		int b = inst & 0xf;
		TRACE("sto.l");
		addr += cpu.regs[a];
		wlat (opc, addr, cpu.regs[b]);
		pc += 4;
	      }
	      break;
	    case 0x0e: /* cmp */
	      {
		int a  = (inst >> 4) & 0xf;
		int b  = inst & 0xf;
		int cc = 0;
		int va = cpu.regs[a];
		int vb = cpu.regs[b]; 

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

		cpu.cc = cc;
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
		cpu.exception = SIGILL;
		break;
	      }
	    case 0x19: /* jsr */
	      {
		unsigned int fn = cpu.regs[(inst >> 4) & 0xf];
		unsigned int sp = cpu.regs[1];

		TRACE("jsr");

 		/* Save a slot for the static chain.  */
		sp -= 4;

		/* Push the return address.  */
		sp -= 4;
		wlat (opc, sp, pc + 2);
		
		/* Push the current frame pointer.  */
		sp -= 4;
		wlat (opc, sp, cpu.regs[0]);

		/* Uncache the stack pointer and set the fp & pc.  */
		cpu.regs[1] = sp;
		cpu.regs[0] = sp;
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
		cpu.regs[reg] = val;
		pc += 4;
	      }
	      break;
	    case 0x1c: /* ld.b (register indirect) */
	      {
		int src  = inst & 0xf;
		int dest = (inst >> 4) & 0xf;
		int xv;
		TRACE("ld.b");
		xv = cpu.regs[src];
		cpu.regs[dest] = rbat (opc, xv);
	      }
	      break;
	    case 0x1d: /* lda.b */
	      {
		int reg = (inst >> 4) & 0xf;
		unsigned int addr = EXTRACT_WORD(pc+2);
		TRACE("lda.b");
		cpu.regs[reg] = rbat (opc, addr);
		pc += 4;
	      }
	      break;
	    case 0x1e: /* st.b */
	      {
		int dest = (inst >> 4) & 0xf;
		int val  = inst & 0xf;
		TRACE("st.b");
		wbat (opc, cpu.regs[dest], cpu.regs[val]);
	      }
	      break;
	    case 0x1f: /* sta.b */
	      {
		int reg = (inst >> 4) & 0xf;
		unsigned int addr = EXTRACT_WORD(pc+2);
		TRACE("sta.b");
		wbat (opc, addr, cpu.regs[reg]);
		pc += 4;
	      }
	      break;
	    case 0x20: /* ldi.s (immediate) */
	      {
		int reg = (inst >> 4) & 0xf;

		unsigned int val = EXTRACT_WORD(pc+2);
		TRACE("ldi.s");
		cpu.regs[reg] = val;
		pc += 4;
	      }
	      break;
	    case 0x21: /* ld.s (register indirect) */
	      {
		int src  = inst & 0xf;
		int dest = (inst >> 4) & 0xf;
		int xv;
		TRACE("ld.s");
		xv = cpu.regs[src];
		switch (xv) {
		case MARIN_UART_RXRDY:
		  cpu.regs[dest] = SIM_TERM_GETC(1) == -1 ? 0 : 1;
		  break;
		case MARIN_UART_RXDATA:
		{
		  int ch = SIM_TERM_GETC(0);
		  cpu.regs[dest] = ch == -1 ? 0 : ch;
		  break;
		}
		case MARIN_UART_TXRDY:
		  cpu.regs[dest] = 1; // XXX always ready
		  break;
		default:
		  cpu.regs[dest] = rsat (opc, xv);
		}
	      }
	      break;
	    case 0x22: /* lda.s */
	      {
		int reg = (inst >> 4) & 0xf;
		unsigned int addr = EXTRACT_WORD(pc+2);
		TRACE("lda.s");
		cpu.regs[reg] = rsat (opc, addr);
		pc += 4;
	      }
	      break;
	    case 0x23: /* st.s */
	      {
		int dest = (inst >> 4) & 0xf;
		int val  = inst & 0xf;
		TRACE("st.s");
		switch (cpu.regs[dest]) {
		case MARIN_UART_TXDATA:
		  //printf("Console output  %d'\n", 
		  //	 cpu.regs[val]);
		  SIM_TERM_PUTC(cpu.regs[val]);
		  break;
		default:
		  wsat (opc, cpu.regs[dest], cpu.regs[val]);
		}
	      }
	      break;
	    case 0x24: /* sta.s */
	      {
		int reg = (inst >> 4) & 0xf;
		unsigned int addr = EXTRACT_WORD(pc+2);
		TRACE("sta.s");
		wsat (opc, addr, cpu.regs[reg]);
		pc += 4;
	      }
	      break;
	    case 0x25: /* jmp */
	      {
		int reg = (inst >> 4) & 0xf;
		TRACE("jmp");
		pc = cpu.regs[reg] - 2;
	      }
	      break;
	    case 0x26: /* and */
	      {
		int a = (inst >> 4) & 0xf;
		int b = inst & 0xf;
		int av, bv;
		TRACE("and");
		av = cpu.regs[a];
		bv = cpu.regs[b];
		cpu.regs[a] = av & bv;
	      }
	      break;
	    case 0x27: /* lshr */
	      {
		int a = (inst >> 4) & 0xf;
		int b = inst & 0xf;
		int av = cpu.regs[a];
		int bv = cpu.regs[b];
		TRACE("lshr");
		cpu.regs[a] = (unsigned) ((unsigned) av >> bv);
	      }
	      break;
	    case 0x28: /* ashl */
	      {
		int a = (inst >> 4) & 0xf;
		int b = inst & 0xf;
		int av = cpu.regs[a];
		int bv = cpu.regs[b];
		TRACE("ashl");
		cpu.regs[a] = av << bv;
	      }
	      break;
	    case 0x29: /* sub.l */
	      {
		int a = (inst >> 4) & 0xf;
		int b = inst & 0xf;
		unsigned av = cpu.regs[a];
		unsigned bv = cpu.regs[b];
		TRACE("sub.l");
		cpu.regs[a] = av - bv;
	      }
	      break;
	    case 0x2a: /* neg */
	      {
		int a  = (inst >> 4) & 0xf;
		int b  = inst & 0xf;
		int bv = cpu.regs[b];
		TRACE("neg");
		cpu.regs[a] = - bv;
	      }
	      break;
	    case 0x2b: /* or */
	      {
		int a = (inst >> 4) & 0xf;
		int b = inst & 0xf;
		int av, bv;
		TRACE("or");
		av = cpu.regs[a];
		bv = cpu.regs[b];
		cpu.regs[a] = av | bv;
	      }
	      break;
	    case 0x2c: /* not */
	      {
		int a = (inst >> 4) & 0xf;
		int b = inst & 0xf;
		int bv = cpu.regs[b];
		TRACE("not");
		cpu.regs[a] = 0xffffffff ^ bv;
	      }
	      break;
	    case 0x2d: /* ashr */
	      {
		int a  = (inst >> 4) & 0xf;
		int b  = inst & 0xf;
		int av = cpu.regs[a];
		int bv = cpu.regs[b];
		TRACE("ashr");
		cpu.regs[a] = av >> bv;
	      }
	      break;
	    case 0x2e: /* xor */
	      {
		int a = (inst >> 4) & 0xf;
		int b = inst & 0xf;
		int av, bv;
		TRACE("xor");
		av = cpu.regs[a];
		bv = cpu.regs[b];
		cpu.regs[a] = av ^ bv;
	      }
	      break;
	    case 0x2f: /* mul.l */
	      {
		int a = (inst >> 4) & 0xf;
		int b = inst & 0xf;
		unsigned av = cpu.regs[a];
		unsigned bv = cpu.regs[b];
		TRACE("mul.l");
		cpu.regs[a] = av * bv;
	      }
	      break;
	    case 0x30: /* swi */
	      {
		unsigned int inum = EXTRACT_WORD(pc+2);
		TRACE("swi");
		/* Set the special registers appropriately.  */
		cpu.sregs[2] = 3; /* MOXIE_EX_SWI */
	        cpu.sregs[3] = inum;




		// XXX Implement





		pc += 4;
	      }
	      break;
	    case 0x31: /* div.l */
	      {
		int a = (inst >> 4) & 0xf;
		int b = inst & 0xf;
		int av = cpu.regs[a];
		int bv = cpu.regs[b];
		TRACE("div.l");
		cpu.regs[a] = av / bv;
	      }
	      break;
	    case 0x32: /* udiv.l */
	      {
		int a = (inst >> 4) & 0xf;
		int b = inst & 0xf;
		unsigned int av = cpu.regs[a];
		unsigned int bv = cpu.regs[b];
		TRACE("udiv.l");
		cpu.regs[a] = (av / bv);
	      }
	      break;
	    case 0x33: /* mod.l */
	      {
		int a = (inst >> 4) & 0xf;
		int b = inst & 0xf;
		int av = cpu.regs[a];
		int bv = cpu.regs[b];
		TRACE("mod.l");
		cpu.regs[a] = av % bv;
	      }
	      break;
	    case 0x34: /* umod.l */
	      {
		int a = (inst >> 4) & 0xf;
		int b = inst & 0xf;
		unsigned int av = cpu.regs[a];
		unsigned int bv = cpu.regs[b];
		TRACE("umod.l");
		cpu.regs[a] = (av % bv);
	      }
	      break;
	    case 0x35: /* brk */
	      TRACE("brk");
	      cpu.exception = SIGTRAP;
	      pc -= 2; /* Adjust pc */
	      break;
	    case 0x36: /* ldo.b */
	      {
		unsigned int addr = EXTRACT_WORD(pc+2);
		int a = (inst >> 4) & 0xf;
		int b = inst & 0xf;
		TRACE("ldo.b");
		addr += cpu.regs[b];
		cpu.regs[a] = rbat (opc, addr);
		pc += 4;
	      }
	      break;
	    case 0x37: /* sto.b */
	      {
		unsigned int addr = EXTRACT_WORD(pc+2);
		int a = (inst >> 4) & 0xf;
		int b = inst & 0xf;
		TRACE("sto.b");
		addr += cpu.regs[a];
		wbat (opc, addr, cpu.regs[b]);
		pc += 4;
	      }
	      break;
	    case 0x38: /* ldo.s */
	      {
		unsigned int addr = EXTRACT_WORD(pc+2);
		int a = (inst >> 4) & 0xf;
		int b = inst & 0xf;
		TRACE("ldo.s");
		addr += cpu.regs[b];
		cpu.regs[a] = rsat (opc, addr);
		pc += 4;
	      }
	      break;
	    case 0x39: /* sto.s */
	      {
		unsigned int addr = EXTRACT_WORD(pc+2);
		int a = (inst >> 4) & 0xf;
		int b = inst & 0xf;
		TRACE("sto.s");
		addr += cpu.regs[a];
		wsat (opc, addr, cpu.regs[b]);
		pc += 4;
	      }
	      break;
	    default:
	      opc = opcode;
	      TRACE("SIGILL1");
	      cpu.exception = SIGILL;
	      break;
	    }
	}

      insts++;
      pc += 2;

    } while (!cpu.exception && 
	     (!maxinsns || ((insts - cpu.insts) < maxinsns)));

  /* Hide away the things we've cached while executing.  */
  cpu.regs[PC_REGNO] = pc;
  cpu.insts += insts;		/* instructions done ... */

  signal (SIGINT, sigsave);
}

static void
one_iter(void)
{
  sim_resume(0, 25000);
}


int main(int ac, char *av[])
{
  int fd, val;


  set_initial_gprs ();	/* Reset the GPR registers.  */
  
  cpu.regs[PC_REGNO] = 0x30000000;

#ifndef EMSCRIPTEN
  fd = open(av[1], O_RDONLY);
  
  printf("fd = %d\n", fd);

  val = read(fd, mem, RAM_SIZE);

  printf("Read %d bytes from '%s'\n", val, av[1]);

  sim_resume(0, 0);
#else
  
#if 0
    EM_ASM(
        term = new Terminal({
            termDiv: 'termDiv',
            handler: function() {},
            x: 0, y: 0,
            initHandler: function() {
                term.charMode = true;
                term.lock = false;
                term.cursorOn();
            }
        });
        term.open();
    );
#endif
    //EM_ASM(term = new Terminal(24, 80, 'tty'););
    EM_ASM(moxie_gui = new moxieGUI('tty'););

    //printf("Copying app data to sim ram\n");
  
  memcpy(mem, moxie_binary_data, sizeof(moxie_binary_data));

  //printf("Starting emscripten loop\n");

  emscripten_set_main_loop(one_iter, 1000/50, 0);
#endif

  return 0;
}



int
sim_trace (void)
{
  if (tracefile == 0)
    tracefile = fopen("trace.csv", "wb");

  tracing = 1;
  
  sim_resume (0, 0);

  tracing = 0;
  
  return 1;
}


int
sim_stop (void)
{
  cpu.exception = SIGINT;
  return 1;
}
