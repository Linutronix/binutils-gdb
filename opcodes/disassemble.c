/* Select disassembly routine for specified architecture.
   Copyright (C) 1994, 1995, 1996, 1997 Free Software Foundation, Inc.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#include "ansidecl.h"
#include "dis-asm.h"

#ifdef ARCH_all
#define ARCH_a29k
#define ARCH_alpha
#define ARCH_arc
#define ARCH_arm
#define ARCH_d10v
/* start-sanitize-d30v */
#define ARCH_d30v
/* end-sanitize-d30v */
#define ARCH_h8300
#define ARCH_h8500
#define ARCH_hppa
#define ARCH_i386
#define ARCH_i960
#define ARCH_m32r
#define ARCH_m68k
#define ARCH_m88k
#define ARCH_mips
#define ARCH_mn10200
#define ARCH_mn10300
#define ARCH_ns32k
#define ARCH_powerpc
#define ARCH_rs6000
#define ARCH_sh
#define ARCH_sparc
/* start-sanitize-tic80 */
#define ARCH_tic80
/* end-sanitize-tic80 */
#define ARCH_v850
#define ARCH_w65
#define ARCH_z8k
#endif

disassembler_ftype
disassembler (abfd)
     bfd *abfd;
{
  enum bfd_architecture a = bfd_get_arch (abfd);
  disassembler_ftype disassemble;

  switch (a)
    {
      /* If you add a case to this table, also add it to the
	 ARCH_all definition right above this function.  */
#ifdef ARCH_a29k
    case bfd_arch_a29k:
      /* As far as I know we only handle big-endian 29k objects.  */
      disassemble = print_insn_big_a29k;
      break;
#endif
#ifdef ARCH_alpha
    case bfd_arch_alpha:
      disassemble = print_insn_alpha;
      break;
#endif
#ifdef ARCH_arc
    case bfd_arch_arc:
      {
	disassemble = arc_get_disassembler (bfd_get_mach (abfd),
					    bfd_big_endian (abfd));
	break;
      }
#endif
#ifdef ARCH_arm
    case bfd_arch_arm:
      if (bfd_big_endian (abfd))
	disassemble = print_insn_big_arm;
      else
	disassemble = print_insn_little_arm;
      break;
#endif
#ifdef ARCH_d10v
    case bfd_arch_d10v:
      disassemble = print_insn_d10v;
      break;
#endif
/* start-sanitize-d30v */
#ifdef ARCH_d30v
    case bfd_arch_d30v:
      disassemble = print_insn_d30v;
      break;
#endif
/* end-sanitize-d30v */
#ifdef ARCH_h8300
    case bfd_arch_h8300:
      if (bfd_get_mach(abfd) == bfd_mach_h8300h)
	disassemble = print_insn_h8300h;
      else if (bfd_get_mach(abfd) == bfd_mach_h8300s)
	disassemble = print_insn_h8300s;
      else 
	disassemble = print_insn_h8300;
      break;
#endif
#ifdef ARCH_h8500
    case bfd_arch_h8500:
      disassemble = print_insn_h8500;
      break;
#endif
#ifdef ARCH_hppa
    case bfd_arch_hppa:
      disassemble = print_insn_hppa;
      break;
#endif
#ifdef ARCH_i386
    case bfd_arch_i386:
      disassemble = print_insn_i386;
      break;
#endif
#ifdef ARCH_i960
    case bfd_arch_i960:
      disassemble = print_insn_i960;
      break;
#endif
#ifdef ARCH_m32r
    case bfd_arch_m32r:
      disassemble = print_insn_m32r;
      break;
#endif
#ifdef ARCH_m68k
    case bfd_arch_m68k:
      disassemble = print_insn_m68k;
      break;
#endif
#ifdef ARCH_m88k
    case bfd_arch_m88k:
      disassemble = print_insn_m88k;
      break;
#endif
#ifdef ARCH_ns32k
    case bfd_arch_ns32k:
      disassemble = print_insn_ns32k;
      break;
#endif
#ifdef ARCH_mips
    case bfd_arch_mips:
      if (bfd_big_endian (abfd))
	disassemble = print_insn_big_mips;
      else
	disassemble = print_insn_little_mips;
      break;
#endif
#ifdef ARCH_mn10200
    case bfd_arch_mn10200:
      disassemble = print_insn_mn10200;
      break;
#endif
#ifdef ARCH_mn10300
    case bfd_arch_mn10300:
      disassemble = print_insn_mn10300;
      break;
#endif
#ifdef ARCH_powerpc
    case bfd_arch_powerpc:
      if (bfd_big_endian (abfd))
	disassemble = print_insn_big_powerpc;
      else
	disassemble = print_insn_little_powerpc;
      break;
#endif
#ifdef ARCH_rs6000
    case bfd_arch_rs6000:
      disassemble = print_insn_rs6000;
      break;
#endif
#ifdef ARCH_sh
    case bfd_arch_sh:
      if (bfd_big_endian (abfd))
	disassemble = print_insn_sh;
      else
	disassemble = print_insn_shl;
      break;
#endif
#ifdef ARCH_sparc
    case bfd_arch_sparc:
      disassemble = print_insn_sparc;
      break;
#endif
/* start-sanitize-tic80 */
#ifdef ARCH_tic80
    case bfd_arch_tic80:
      disassemble = print_insn_tic80;
      break;
#endif
/* end-sanitize-tic80 */
#ifdef ARCH_v850
    case bfd_arch_v850:
      disassemble = print_insn_v850;
      break;
#endif
#ifdef ARCH_w65
    case bfd_arch_w65:
      disassemble = print_insn_w65;
      break;
#endif
#ifdef ARCH_z8k
    case bfd_arch_z8k:
      if (bfd_get_mach(abfd) == bfd_mach_z8001)
	disassemble = print_insn_z8001;
      else 
	disassemble = print_insn_z8002;
      break;
#endif
    default:
      return 0;
    }
  return disassemble;
}

/* Notify the disassembler of the address associated with the
   instruction being decoded: */

void
disasm_symaddr (sym, info)
     asymbol *sym;
     disassemble_info *info;
{
#ifdef ARCH_arm
  /* decide if symbol is thumb or not */
  if (info->flavour == bfd_target_coff_flavour)
    {
/* This is not ideal including these here, since we may not be
   building a COFF targetted world at all... so coffsymbol() may not
   be available. (TO BE SORTED OUT) */
#include "coff/internal.h"
#include "libcoff.h"
      coff_symbol_type *cs = coffsymbol (sym);
      if (   cs->native->u.syment.n_sclass == C_THUMBEXT
          || cs->native->u.syment.n_sclass == C_THUMBSTAT
          || cs->native->u.syment.n_sclass == C_THUMBLABEL
          || cs->native->u.syment.n_sclass == C_THUMBEXTFUNC
          || cs->native->u.syment.n_sclass == C_THUMBSTATFUNC)
       info->flags |= 0x1;
      else
       info->flags &= ~0x1;
    }
#endif
  /* Do nothing for other architectures at the moment */
}
