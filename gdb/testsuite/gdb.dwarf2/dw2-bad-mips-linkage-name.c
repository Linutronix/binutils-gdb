/* This testcase is part of GDB, the GNU debugger.

   Copyright 2015-2016 Free Software Foundation, Inc.

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

/* Dummy main function.  */

int
main (void)
{
  asm ("main_label: .globl main_label");
  return 0;
}

/* dummy f function, DWARF will describe arguments and type differently.  */
int
f (char *x)
{
  asm (".global f_end_lbl\nf_end_lbl:");
  return 0;
}

/* dummy g function, DWARF will describe arguments and type differently.  */
int
g (char *x)
{
  asm (".global g_end_lbl\ng_end_lbl:");
  return 0;
}
