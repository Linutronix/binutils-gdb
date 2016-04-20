/* GDB CLI command scripting.

   Copyright (C) 1986-2016 Free Software Foundation, Inc.

   This file is part of GDB.

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

#include "defs.h"
#include "value.h"
#include "language.h"		/* For value_true */
#include <ctype.h>

#include "ui-out.h"
#include "top.h"
#include "breakpoint.h"
#include "cli/cli-cmds.h"
#include "cli/cli-decode.h"
#include "cli/cli-script.h"

#include "extension.h"
#include "interps.h"
#include "compile/compile.h"

/* Prototypes for local functions.  */

static enum command_control_type
recurse_read_control_structure (char * (*read_next_line_func) (void),
				struct command_line *current_cmd,
				void (*validator)(char *, void *),
				void *closure);

static char *insert_args (char *line);

static struct cleanup * setup_user_args (char *p);

static char *read_next_line (void);

/* Level of control structure when reading.  */
static int control_level;

/* Level of control structure when executing.  */
static int command_nest_depth = 1;

/* This is to prevent certain commands being printed twice.  */
static int suppress_next_print_command_trace = 0;

/* Structure for arguments to user defined functions.  */
#define MAXUSERARGS 10
struct user_args
  {
    struct user_args *next;
    /* It is necessary to store a malloced copy of the command line to
       ensure that the arguments are not overwritten before they are
       used.  */
    char *command;
    struct
      {
	char *arg;
	int len;
      }
    a[MAXUSERARGS];
    int count;
  }
 *user_args;


/* Return non-zero if TYPE is a multi-line command (i.e., is terminated
   by "end").  */

static int
multi_line_command_p (enum command_control_type type)
{
  switch (type)
    {
    case if_control:
    case while_control:
    case while_stepping_control:
    case commands_control:
    case compile_control:
    case python_control:
    case guile_control:
      return 1;
    default:
      return 0;
    }
}

/* Allocate, initialize a new command line structure for one of the
   control commands (if/while).  */

static struct command_line *
build_command_line (enum command_control_type type, char *args)
{
  struct command_line *cmd;

  if (args == NULL && (type == if_control || type == while_control))
    error (_("if/while commands require arguments."));
  gdb_assert (args != NULL);

  cmd = XNEW (struct command_line);
  cmd->next = NULL;
  cmd->control_type = type;

  cmd->body_count = 1;
  cmd->body_list = XCNEWVEC (struct command_line *, cmd->body_count);
  cmd->line = xstrdup (args);

  return cmd;
}

/* Build and return a new command structure for the control commands
   such as "if" and "while".  */

struct command_line *
get_command_line (enum command_control_type type, char *arg)
{
  struct command_line *cmd;
  struct cleanup *old_chain = NULL;

  /* Allocate and build a new command line structure.  */
  cmd = build_command_line (type, arg);

  old_chain = make_cleanup_free_command_lines (&cmd);

  /* Read in the body of this command.  */
  if (recurse_read_control_structure (read_next_line, cmd, 0, 0)
      == invalid_control)
    {
      warning (_("Error reading in canned sequence of commands."));
      do_cleanups (old_chain);
      return NULL;
    }

  discard_cleanups (old_chain);
  return cmd;
}

/* Recursively print a command (including full control structures).  */

void
print_command_lines (struct ui_out *uiout, struct command_line *cmd,
		     unsigned int depth)
{
  struct command_line *list;

  list = cmd;
  while (list)
    {
      if (depth)
	ui_out_spaces (uiout, 2 * depth);

      /* A simple command, print it and continue.  */
      if (list->control_type == simple_control)
	{
	  ui_out_field_string (uiout, NULL, list->line);
	  ui_out_text (uiout, "\n");
	  list = list->next;
	  continue;
	}

      /* loop_continue to jump to the start of a while loop, print it
         and continue. */
      if (list->control_type == continue_control)
	{
	  ui_out_field_string (uiout, NULL, "loop_continue");
	  ui_out_text (uiout, "\n");
	  list = list->next;
	  continue;
	}

      /* loop_break to break out of a while loop, print it and
	 continue.  */
      if (list->control_type == break_control)
	{
	  ui_out_field_string (uiout, NULL, "loop_break");
	  ui_out_text (uiout, "\n");
	  list = list->next;
	  continue;
	}

      /* A while command.  Recursively print its subcommands and
	 continue.  */
      if (list->control_type == while_control
	  || list->control_type == while_stepping_control)
	{
	  /* For while-stepping, the line includes the 'while-stepping'
	     token.  See comment in process_next_line for explanation.
	     Here, take care not print 'while-stepping' twice.  */
	  if (list->control_type == while_control)
	    ui_out_field_fmt (uiout, NULL, "while %s", list->line);
	  else
	    ui_out_field_string (uiout, NULL, list->line);
	  ui_out_text (uiout, "\n");
	  print_command_lines (uiout, *list->body_list, depth + 1);
	  if (depth)
	    ui_out_spaces (uiout, 2 * depth);
	  ui_out_field_string (uiout, NULL, "end");
	  ui_out_text (uiout, "\n");
	  list = list->next;
	  continue;
	}

      /* An if command.  Recursively print both arms before
	 continueing.  */
      if (list->control_type == if_control)
	{
	  ui_out_field_fmt (uiout, NULL, "if %s", list->line);
	  ui_out_text (uiout, "\n");
	  /* The true arm.  */
	  print_command_lines (uiout, list->body_list[0], depth + 1);

	  /* Show the false arm if it exists.  */
	  if (list->body_count == 2)
	    {
	      if (depth)
		ui_out_spaces (uiout, 2 * depth);
	      ui_out_field_string (uiout, NULL, "else");
	      ui_out_text (uiout, "\n");
	      print_command_lines (uiout, list->body_list[1], depth + 1);
	    }

	  if (depth)
	    ui_out_spaces (uiout, 2 * depth);
	  ui_out_field_string (uiout, NULL, "end");
	  ui_out_text (uiout, "\n");
	  list = list->next;
	  continue;
	}

      /* A commands command.  Print the breakpoint commands and
	 continue.  */
      if (list->control_type == commands_control)
	{
	  if (*(list->line))
	    ui_out_field_fmt (uiout, NULL, "commands %s", list->line);
	  else
	    ui_out_field_string (uiout, NULL, "commands");
	  ui_out_text (uiout, "\n");
	  print_command_lines (uiout, *list->body_list, depth + 1);
	  if (depth)
	    ui_out_spaces (uiout, 2 * depth);
	  ui_out_field_string (uiout, NULL, "end");
	  ui_out_text (uiout, "\n");
	  list = list->next;
	  continue;
	}

      if (list->control_type == python_control)
	{
	  ui_out_field_string (uiout, NULL, "python");
	  ui_out_text (uiout, "\n");
	  /* Don't indent python code at all.  */
	  print_command_lines (uiout, *list->body_list, 0);
	  if (depth)
	    ui_out_spaces (uiout, 2 * depth);
	  ui_out_field_string (uiout, NULL, "end");
	  ui_out_text (uiout, "\n");
	  list = list->next;
	  continue;
	}

      if (list->control_type == compile_control)
	{
	  ui_out_field_string (uiout, NULL, "compile expression");
	  ui_out_text (uiout, "\n");
	  print_command_lines (uiout, *list->body_list, 0);
	  if (depth)
	    ui_out_spaces (uiout, 2 * depth);
	  ui_out_field_string (uiout, NULL, "end");
	  ui_out_text (uiout, "\n");
	  list = list->next;
	  continue;
	}

      if (list->control_type == guile_control)
	{
	  ui_out_field_string (uiout, NULL, "guile");
	  ui_out_text (uiout, "\n");
	  print_command_lines (uiout, *list->body_list, depth + 1);
	  if (depth)
	    ui_out_spaces (uiout, 2 * depth);
	  ui_out_field_string (uiout, NULL, "end");
	  ui_out_text (uiout, "\n");
	  list = list->next;
	  continue;
	}

      /* Ignore illegal command type and try next.  */
      list = list->next;
    }				/* while (list) */
}

/* Handle pre-post hooks.  */

static void
clear_hook_in_cleanup (void *data)
{
  struct cmd_list_element *c = (struct cmd_list_element *) data;

  c->hook_in = 0; /* Allow hook to work again once it is complete.  */
}

void
execute_cmd_pre_hook (struct cmd_list_element *c)
{
  if ((c->hook_pre) && (!c->hook_in))
    {
      struct cleanup *cleanups = make_cleanup (clear_hook_in_cleanup, c);
      c->hook_in = 1; /* Prevent recursive hooking.  */
      execute_user_command (c->hook_pre, (char *) 0);
      do_cleanups (cleanups);
    }
}

void
execute_cmd_post_hook (struct cmd_list_element *c)
{
  if ((c->hook_post) && (!c->hook_in))
    {
      struct cleanup *cleanups = make_cleanup (clear_hook_in_cleanup, c);

      c->hook_in = 1; /* Prevent recursive hooking.  */
      execute_user_command (c->hook_post, (char *) 0);
      do_cleanups (cleanups);
    }
}

/* Execute the command in CMD.  */
static void
do_restore_user_call_depth (void * call_depth)
{	
  int *depth = (int *) call_depth;

  (*depth)--;
  if ((*depth) == 0)
    in_user_command = 0;
}


void
execute_user_command (struct cmd_list_element *c, char *args)
{
  struct ui *ui = current_ui;
  struct command_line *cmdlines;
  struct cleanup *old_chain;
  enum command_control_type ret;
  static int user_call_depth = 0;
  extern unsigned int max_user_call_depth;

  cmdlines = c->user_commands;
  if (cmdlines == 0)
    /* Null command */
    return;

  old_chain = setup_user_args (args);

  if (++user_call_depth > max_user_call_depth)
    error (_("Max user call depth exceeded -- command aborted."));

  make_cleanup (do_restore_user_call_depth, &user_call_depth);

  /* Set the instream to 0, indicating execution of a
     user-defined function.  */
  make_cleanup (do_restore_instream_cleanup, ui->instream);
  ui->instream = NULL;

  /* Also set the global in_user_command, so that NULL instream is
     not confused with Insight.  */
  in_user_command = 1;

  make_cleanup_restore_integer (&current_ui->async);
  current_ui->async = 0;

  command_nest_depth++;
  while (cmdlines)
    {
      ret = execute_control_command (cmdlines);
      if (ret != simple_control && ret != break_control)
	{
	  warning (_("Error executing canned sequence of commands."));
	  break;
	}
      cmdlines = cmdlines->next;
    }
  command_nest_depth--;
  do_cleanups (old_chain);
}

/* This function is called every time GDB prints a prompt.  It ensures
   that errors and the like do not confuse the command tracing.  */

void
reset_command_nest_depth (void)
{
  command_nest_depth = 1;

  /* Just in case.  */
  suppress_next_print_command_trace = 0;
}

/* Print the command, prefixed with '+' to represent the call depth.
   This is slightly complicated because this function may be called
   from execute_command and execute_control_command.  Unfortunately
   execute_command also prints the top level control commands.
   In these cases execute_command will call execute_control_command
   via while_command or if_command.  Inner levels of 'if' and 'while'
   are dealt with directly.  Therefore we can use these functions
   to determine whether the command has been printed already or not.  */
void
print_command_trace (const char *cmd)
{
  int i;

  if (suppress_next_print_command_trace)
    {
      suppress_next_print_command_trace = 0;
      return;
    }

  if (!source_verbose && !trace_commands)
    return;

  for (i=0; i < command_nest_depth; i++)
    printf_filtered ("+");

  printf_filtered ("%s\n", cmd);
}

enum command_control_type
execute_control_command (struct command_line *cmd)
{
  struct expression *expr;
  struct command_line *current;
  struct cleanup *old_chain = make_cleanup (null_cleanup, 0);
  struct value *val;
  struct value *val_mark;
  int loop;
  enum command_control_type ret;
  char *new_line;

  /* Start by assuming failure, if a problem is detected, the code
     below will simply "break" out of the switch.  */
  ret = invalid_control;

  switch (cmd->control_type)
    {
    case simple_control:
      /* A simple command, execute it and return.  */
      new_line = insert_args (cmd->line);
      if (!new_line)
	break;
      make_cleanup (free_current_contents, &new_line);
      execute_command (new_line, 0);
      ret = cmd->control_type;
      break;

    case continue_control:
      print_command_trace ("loop_continue");

      /* Return for "continue", and "break" so we can either
         continue the loop at the top, or break out.  */
      ret = cmd->control_type;
      break;

    case break_control:
      print_command_trace ("loop_break");

      /* Return for "continue", and "break" so we can either
         continue the loop at the top, or break out.  */
      ret = cmd->control_type;
      break;

    case while_control:
      {
	int len = strlen (cmd->line) + 7;
	char *buffer = (char *) alloca (len);

	xsnprintf (buffer, len, "while %s", cmd->line);
	print_command_trace (buffer);

	/* Parse the loop control expression for the while statement.  */
	new_line = insert_args (cmd->line);
	if (!new_line)
	  break;
	make_cleanup (free_current_contents, &new_line);
	expr = parse_expression (new_line);
	make_cleanup (free_current_contents, &expr);

	ret = simple_control;
	loop = 1;

	/* Keep iterating so long as the expression is true.  */
	while (loop == 1)
	  {
	    int cond_result;

	    QUIT;

	    /* Evaluate the expression.  */
	    val_mark = value_mark ();
	    val = evaluate_expression (expr);
	    cond_result = value_true (val);
	    value_free_to_mark (val_mark);

	    /* If the value is false, then break out of the loop.  */
	    if (!cond_result)
	      break;

	    /* Execute the body of the while statement.  */
	    current = *cmd->body_list;
	    while (current)
	      {
		command_nest_depth++;
		ret = execute_control_command (current);
		command_nest_depth--;

		/* If we got an error, or a "break" command, then stop
		   looping.  */
		if (ret == invalid_control || ret == break_control)
		  {
		    loop = 0;
		    break;
		  }

		/* If we got a "continue" command, then restart the loop
		   at this point.  */
		if (ret == continue_control)
		  break;

		/* Get the next statement.  */
		current = current->next;
	      }
	  }

	/* Reset RET so that we don't recurse the break all the way down.  */
	if (ret == break_control)
	  ret = simple_control;

	break;
      }

    case if_control:
      {
	int len = strlen (cmd->line) + 4;
	char *buffer = (char *) alloca (len);

	xsnprintf (buffer, len, "if %s", cmd->line);
	print_command_trace (buffer);

	new_line = insert_args (cmd->line);
	if (!new_line)
	  break;
	make_cleanup (free_current_contents, &new_line);
	/* Parse the conditional for the if statement.  */
	expr = parse_expression (new_line);
	make_cleanup (free_current_contents, &expr);

	current = NULL;
	ret = simple_control;

	/* Evaluate the conditional.  */
	val_mark = value_mark ();
	val = evaluate_expression (expr);

	/* Choose which arm to take commands from based on the value
	   of the conditional expression.  */
	if (value_true (val))
	  current = *cmd->body_list;
	else if (cmd->body_count == 2)
	  current = *(cmd->body_list + 1);
	value_free_to_mark (val_mark);

	/* Execute commands in the given arm.  */
	while (current)
	  {
	    command_nest_depth++;
	    ret = execute_control_command (current);
	    command_nest_depth--;

	    /* If we got an error, get out.  */
	    if (ret != simple_control)
	      break;

	    /* Get the next statement in the body.  */
	    current = current->next;
	  }

	break;
      }

    case commands_control:
      {
	/* Breakpoint commands list, record the commands in the
	   breakpoint's command list and return.  */
	new_line = insert_args (cmd->line);
	if (!new_line)
	  break;
	make_cleanup (free_current_contents, &new_line);
	ret = commands_from_control_command (new_line, cmd);
	break;
      }

    case compile_control:
      eval_compile_command (cmd, NULL, cmd->control_u.compile.scope,
			    cmd->control_u.compile.scope_data);
      ret = simple_control;
      break;

    case python_control:
    case guile_control:
      {
	eval_ext_lang_from_control_command (cmd);
	ret = simple_control;
	break;
      }

    default:
      warning (_("Invalid control type in canned commands structure."));
      break;
    }

  do_cleanups (old_chain);

  return ret;
}

/* Like execute_control_command, but first set
   suppress_next_print_command_trace.  */

enum command_control_type
execute_control_command_untraced (struct command_line *cmd)
{
  suppress_next_print_command_trace = 1;
  return execute_control_command (cmd);
}


/* "while" command support.  Executes a body of statements while the
   loop condition is nonzero.  */

static void
while_command (char *arg, int from_tty)
{
  struct command_line *command = NULL;
  struct cleanup *old_chain;

  control_level = 1;
  command = get_command_line (while_control, arg);

  if (command == NULL)
    return;

  old_chain = make_cleanup_restore_integer (&current_ui->async);
  current_ui->async = 0;

  execute_control_command_untraced (command);
  free_command_lines (&command);

  do_cleanups (old_chain);
}

/* "if" command support.  Execute either the true or false arm depending
   on the value of the if conditional.  */

static void
if_command (char *arg, int from_tty)
{
  struct command_line *command = NULL;
  struct cleanup *old_chain;

  control_level = 1;
  command = get_command_line (if_control, arg);

  if (command == NULL)
    return;

  old_chain = make_cleanup_restore_integer (&current_ui->async);
  current_ui->async = 0;

  execute_control_command_untraced (command);
  free_command_lines (&command);

  do_cleanups (old_chain);
}

/* Cleanup */
static void
arg_cleanup (void *ignore)
{
  struct user_args *oargs = user_args;

  if (!user_args)
    internal_error (__FILE__, __LINE__,
		    _("arg_cleanup called with no user args.\n"));

  user_args = user_args->next;
  xfree (oargs->command);
  xfree (oargs);
}

/* Bind the incomming arguments for a user defined command to
   $arg0, $arg1 ... $argMAXUSERARGS.  */

static struct cleanup *
setup_user_args (char *p)
{
  struct user_args *args;
  struct cleanup *old_chain;
  unsigned int arg_count = 0;

  args = XNEW (struct user_args);
  memset (args, 0, sizeof (struct user_args));

  args->next = user_args;
  user_args = args;

  old_chain = make_cleanup (arg_cleanup, 0/*ignored*/);

  if (p == NULL)
    return old_chain;

  user_args->command = p = xstrdup (p);

  while (*p)
    {
      char *start_arg;
      int squote = 0;
      int dquote = 0;
      int bsquote = 0;

      if (arg_count >= MAXUSERARGS)
	error (_("user defined function may only have %d arguments."),
	       MAXUSERARGS);

      /* Strip whitespace.  */
      while (*p == ' ' || *p == '\t')
	p++;

      /* P now points to an argument.  */
      start_arg = p;
      user_args->a[arg_count].arg = p;

      /* Get to the end of this argument.  */
      while (*p)
	{
	  if (((*p == ' ' || *p == '\t')) && !squote && !dquote && !bsquote)
	    break;
	  else
	    {
	      if (bsquote)
		bsquote = 0;
	      else if (*p == '\\')
		bsquote = 1;
	      else if (squote)
		{
		  if (*p == '\'')
		    squote = 0;
		}
	      else if (dquote)
		{
		  if (*p == '"')
		    dquote = 0;
		}
	      else
		{
		  if (*p == '\'')
		    squote = 1;
		  else if (*p == '"')
		    dquote = 1;
		}
	      p++;
	    }
	}

      user_args->a[arg_count].len = p - start_arg;
      arg_count++;
      user_args->count++;
    }
  return old_chain;
}

/* Given character string P, return a point to the first argument
   ($arg), or NULL if P contains no arguments.  */

static char *
locate_arg (char *p)
{
  while ((p = strchr (p, '$')))
    {
      if (startswith (p, "$arg")
	  && (isdigit (p[4]) || p[4] == 'c'))
	return p;
      p++;
    }
  return NULL;
}

/* Insert the user defined arguments stored in user_arg into the $arg
   arguments found in line, with the updated copy being placed into
   nline.  */

static char *
insert_args (char *line)
{
  char *p, *save_line, *new_line;
  unsigned len, i;

  /* If we are not in a user-defined function, treat $argc, $arg0, et
     cetera as normal convenience variables.  */
  if (user_args == NULL)
    return xstrdup (line);

  /* First we need to know how much memory to allocate for the new
     line.  */
  save_line = line;
  len = 0;
  while ((p = locate_arg (line)))
    {
      len += p - line;
      i = p[4] - '0';

      if (p[4] == 'c')
	{
	  /* $argc.  Number will be <=10.  */
	  len += user_args->count == 10 ? 2 : 1;
	}
      else if (i >= user_args->count)
	{
	  error (_("Missing argument %d in user function."), i);
	  return NULL;
	}
      else
	{
	  len += user_args->a[i].len;
	}
      line = p + 5;
    }

  /* Don't forget the tail.  */
  len += strlen (line);

  /* Allocate space for the new line and fill it in.  */
  new_line = (char *) xmalloc (len + 1);
  if (new_line == NULL)
    return NULL;

  /* Restore pointer to beginning of old line.  */
  line = save_line;

  /* Save pointer to beginning of new line.  */
  save_line = new_line;

  while ((p = locate_arg (line)))
    {
      int i, len;

      memcpy (new_line, line, p - line);
      new_line += p - line;

      if (p[4] == 'c')
	{
	  gdb_assert (user_args->count >= 0 && user_args->count <= 10);
	  if (user_args->count == 10)
	    {
	      *(new_line++) = '1';
	      *(new_line++) = '0';
	    }
	  else
	    *(new_line++) = user_args->count + '0';
	}
      else
	{
	  i = p[4] - '0';
	  len = user_args->a[i].len;
	  if (len)
	    {
	      memcpy (new_line, user_args->a[i].arg, len);
	      new_line += len;
	    }
	}
      line = p + 5;
    }
  /* Don't forget the tail.  */
  strcpy (new_line, line);

  /* Return a pointer to the beginning of the new line.  */
  return save_line;
}


/* Expand the body_list of COMMAND so that it can hold NEW_LENGTH
   code bodies.  This is typically used when we encounter an "else"
   clause for an "if" command.  */

static void
realloc_body_list (struct command_line *command, int new_length)
{
  int n;
  struct command_line **body_list;

  n = command->body_count;

  /* Nothing to do?  */
  if (new_length <= n)
    return;

  body_list = XCNEWVEC (struct command_line *, new_length);

  memcpy (body_list, command->body_list, sizeof (struct command_line *) * n);

  xfree (command->body_list);
  command->body_list = body_list;
  command->body_count = new_length;
}

/* Read next line from stdin.  Passed to read_command_line_1 and
   recurse_read_control_structure whenever we need to read commands
   from stdin.  */

static char *
read_next_line (void)
{
  struct ui *ui = current_ui;
  char *prompt_ptr, control_prompt[256];
  int i = 0;

  if (control_level >= 254)
    error (_("Control nesting too deep!"));

  /* Set a prompt based on the nesting of the control commands.  */
  if (ui->instream == stdin
      || (ui->instream == 0 && deprecated_readline_hook != NULL))
    {
      for (i = 0; i < control_level; i++)
	control_prompt[i] = ' ';
      control_prompt[i] = '>';
      control_prompt[i + 1] = '\0';
      prompt_ptr = (char *) &control_prompt[0];
    }
  else
    prompt_ptr = NULL;

  return command_line_input (prompt_ptr, ui->instream == stdin, "commands");
}

/* Process one input line.  If the command is an "end", return such an
   indication to the caller.  If PARSE_COMMANDS is true, strip leading
   whitespace (trailing whitespace is always stripped) in the line,
   attempt to recognize GDB control commands, and also return an
   indication if the command is an "else" or a nop.

   Otherwise, only "end" is recognized.  */

static enum misc_command_type
process_next_line (char *p, struct command_line **command, int parse_commands,
		   void (*validator)(char *, void *), void *closure)
{
  char *p_end;
  char *p_start;
  int not_handled = 0;

  /* Not sure what to do here.  */
  if (p == NULL)
    return end_command;

  /* Strip trailing whitespace.  */
  p_end = p + strlen (p);
  while (p_end > p && (p_end[-1] == ' ' || p_end[-1] == '\t'))
    p_end--;

  p_start = p;
  /* Strip leading whitespace.  */
  while (p_start < p_end && (*p_start == ' ' || *p_start == '\t'))
    p_start++;

  /* 'end' is always recognized, regardless of parse_commands value.
     We also permit whitespace before end and after.  */
  if (p_end - p_start == 3 && startswith (p_start, "end"))
    return end_command;
  
  if (parse_commands)
    {
      /* If commands are parsed, we skip initial spaces.  Otherwise,
	 which is the case for Python commands and documentation
	 (see the 'document' command), spaces are preserved.  */
      p = p_start;

      /* Blanks and comments don't really do anything, but we need to
	 distinguish them from else, end and other commands which can
	 be executed.  */
      if (p_end == p || p[0] == '#')
	return nop_command;

      /* Is the else clause of an if control structure?  */
      if (p_end - p == 4 && startswith (p, "else"))
	return else_command;

      /* Check for while, if, break, continue, etc and build a new
	 command line structure for them.  */
      if ((p_end - p >= 14 && startswith (p, "while-stepping"))
	  || (p_end - p >= 8 && startswith (p, "stepping"))
	  || (p_end - p >= 2 && startswith (p, "ws")))
	{
	  /* Because validate_actionline and encode_action lookup
	     command's line as command, we need the line to
	     include 'while-stepping'.

	     For 'ws' alias, the command will have 'ws', not expanded
	     to 'while-stepping'.  This is intentional -- we don't
	     really want frontend to send a command list with 'ws',
	     and next break-info returning command line with
	     'while-stepping'.  This should work, but might cause the
	     breakpoint to be marked as changed while it's actually
	     not.  */
	  *command = build_command_line (while_stepping_control, p);
	}
      else if (p_end - p > 5 && startswith (p, "while"))
	{
	  char *first_arg;

	  first_arg = p + 5;
	  while (first_arg < p_end && isspace (*first_arg))
	    first_arg++;
	  *command = build_command_line (while_control, first_arg);
	}
      else if (p_end - p > 2 && startswith (p, "if"))
	{
	  char *first_arg;

	  first_arg = p + 2;
	  while (first_arg < p_end && isspace (*first_arg))
	    first_arg++;
	  *command = build_command_line (if_control, first_arg);
	}
      else if (p_end - p >= 8 && startswith (p, "commands"))
	{
	  char *first_arg;

	  first_arg = p + 8;
	  while (first_arg < p_end && isspace (*first_arg))
	    first_arg++;
	  *command = build_command_line (commands_control, first_arg);
	}
      else if (p_end - p == 6 && startswith (p, "python"))
	{
	  /* Note that we ignore the inline "python command" form
	     here.  */
	  *command = build_command_line (python_control, "");
	}
      else if (p_end - p == 6 && startswith (p, "compile"))
	{
	  /* Note that we ignore the inline "compile command" form
	     here.  */
	  *command = build_command_line (compile_control, "");
	  (*command)->control_u.compile.scope = COMPILE_I_INVALID_SCOPE;
	}

      else if (p_end - p == 5 && startswith (p, "guile"))
	{
	  /* Note that we ignore the inline "guile command" form here.  */
	  *command = build_command_line (guile_control, "");
	}
      else if (p_end - p == 10 && startswith (p, "loop_break"))
	{
	  *command = XNEW (struct command_line);
	  (*command)->next = NULL;
	  (*command)->line = NULL;
	  (*command)->control_type = break_control;
	  (*command)->body_count = 0;
	  (*command)->body_list = NULL;
	}
      else if (p_end - p == 13 && startswith (p, "loop_continue"))
	{
	  *command = XNEW (struct command_line);
	  (*command)->next = NULL;
	  (*command)->line = NULL;
	  (*command)->control_type = continue_control;
	  (*command)->body_count = 0;
	  (*command)->body_list = NULL;
	}
      else
	not_handled = 1;
    }

  if (!parse_commands || not_handled)
    {
      /* A normal command.  */
      *command = XNEW (struct command_line);
      (*command)->next = NULL;
      (*command)->line = savestring (p, p_end - p);
      (*command)->control_type = simple_control;
      (*command)->body_count = 0;
      (*command)->body_list = NULL;
    }

  if (validator)
    {

      TRY
	{
	  validator ((*command)->line, closure);
	}
      CATCH (ex, RETURN_MASK_ALL)
	{
	  xfree (*command);
	  throw_exception (ex);
	}
      END_CATCH
    }

  /* Nothing special.  */
  return ok_command;
}

/* Recursively read in the control structures and create a
   command_line structure from them.  Use read_next_line_func to
   obtain lines of the command.  */

static enum command_control_type
recurse_read_control_structure (char * (*read_next_line_func) (void),
				struct command_line *current_cmd,
				void (*validator)(char *, void *),
				void *closure)
{
  int current_body, i;
  enum misc_command_type val;
  enum command_control_type ret;
  struct command_line **body_ptr, *child_tail, *next;

  child_tail = NULL;
  current_body = 1;

  /* Sanity checks.  */
  if (current_cmd->control_type == simple_control)
    error (_("Recursed on a simple control type."));

  if (current_body > current_cmd->body_count)
    error (_("Allocated body is smaller than this command type needs."));

  /* Read lines from the input stream and build control structures.  */
  while (1)
    {
      dont_repeat ();

      next = NULL;
      val = process_next_line (read_next_line_func (), &next, 
			       current_cmd->control_type != python_control
			       && current_cmd->control_type != guile_control
			       && current_cmd->control_type != compile_control,
			       validator, closure);

      /* Just skip blanks and comments.  */
      if (val == nop_command)
	continue;

      if (val == end_command)
	{
	  if (multi_line_command_p (current_cmd->control_type))
	    {
	      /* Success reading an entire canned sequence of commands.  */
	      ret = simple_control;
	      break;
	    }
	  else
	    {
	      ret = invalid_control;
	      break;
	    }
	}

      /* Not the end of a control structure.  */
      if (val == else_command)
	{
	  if (current_cmd->control_type == if_control
	      && current_body == 1)
	    {
	      realloc_body_list (current_cmd, 2);
	      current_body = 2;
	      child_tail = NULL;
	      continue;
	    }
	  else
	    {
	      ret = invalid_control;
	      break;
	    }
	}

      if (child_tail)
	{
	  child_tail->next = next;
	}
      else
	{
	  body_ptr = current_cmd->body_list;
	  for (i = 1; i < current_body; i++)
	    body_ptr++;

	  *body_ptr = next;

	}

      child_tail = next;

      /* If the latest line is another control structure, then recurse
         on it.  */
      if (multi_line_command_p (next->control_type))
	{
	  control_level++;
	  ret = recurse_read_control_structure (read_next_line_func, next,
						validator, closure);
	  control_level--;

	  if (ret != simple_control)
	    break;
	}
    }

  dont_repeat ();

  return ret;
}

static void
restore_interp (void *arg)
{
  interp_set_temp (interp_name ((struct interp *)arg));
}

/* Read lines from the input stream and accumulate them in a chain of
   struct command_line's, which is then returned.  For input from a
   terminal, the special command "end" is used to mark the end of the
   input, and is not included in the returned chain of commands.

   If PARSE_COMMANDS is true, strip leading whitespace (trailing whitespace
   is always stripped) in the line and attempt to recognize GDB control
   commands.  Otherwise, only "end" is recognized.  */

#define END_MESSAGE "End with a line saying just \"end\"."

struct command_line *
read_command_lines (char *prompt_arg, int from_tty, int parse_commands,
		    void (*validator)(char *, void *), void *closure)
{
  struct command_line *head;

  if (from_tty && input_interactive_p ())
    {
      if (deprecated_readline_begin_hook)
	{
	  /* Note - intentional to merge messages with no newline.  */
	  (*deprecated_readline_begin_hook) ("%s  %s\n", prompt_arg,
					     END_MESSAGE);
	}
      else
	{
	  printf_unfiltered ("%s\n%s\n", prompt_arg, END_MESSAGE);
	  gdb_flush (gdb_stdout);
	}
    }


  /* Reading commands assumes the CLI behavior, so temporarily
     override the current interpreter with CLI.  */
  if (current_interp_named_p (INTERP_CONSOLE))
    head = read_command_lines_1 (read_next_line, parse_commands,
				 validator, closure);
  else
    {
      struct interp *old_interp = interp_set_temp (INTERP_CONSOLE);
      struct cleanup *old_chain = make_cleanup (restore_interp, old_interp);

      head = read_command_lines_1 (read_next_line, parse_commands,
				   validator, closure);
      do_cleanups (old_chain);
    }

  if (deprecated_readline_end_hook && from_tty && input_interactive_p ())
    {
      (*deprecated_readline_end_hook) ();
    }
  return (head);
}

/* Act the same way as read_command_lines, except that each new line is
   obtained using READ_NEXT_LINE_FUNC.  */

struct command_line *
read_command_lines_1 (char * (*read_next_line_func) (void), int parse_commands,
		      void (*validator)(char *, void *), void *closure)
{
  struct command_line *head, *tail, *next;
  struct cleanup *old_chain = make_cleanup (null_cleanup, NULL);
  enum command_control_type ret;
  enum misc_command_type val;

  control_level = 0;
  head = tail = NULL;

  while (1)
    {
      dont_repeat ();
      val = process_next_line (read_next_line_func (), &next, parse_commands,
			       validator, closure);

      /* Ignore blank lines or comments.  */
      if (val == nop_command)
	continue;

      if (val == end_command)
	{
	  ret = simple_control;
	  break;
	}

      if (val != ok_command)
	{
	  ret = invalid_control;
	  break;
	}

      if (multi_line_command_p (next->control_type))
	{
	  control_level++;
	  ret = recurse_read_control_structure (read_next_line_func, next,
						validator, closure);
	  control_level--;

	  if (ret == invalid_control)
	    break;
	}

      if (tail)
	{
	  tail->next = next;
	}
      else
	{
	  head = next;
	  make_cleanup_free_command_lines (&head);
	}
      tail = next;
    }

  dont_repeat ();

  if (ret != invalid_control)
    discard_cleanups (old_chain);
  else
    do_cleanups (old_chain);

  return head;
}

/* Free a chain of struct command_line's.  */

void
free_command_lines (struct command_line **lptr)
{
  struct command_line *l = *lptr;
  struct command_line *next;
  struct command_line **blist;
  int i;

  while (l)
    {
      if (l->body_count > 0)
	{
	  blist = l->body_list;
	  for (i = 0; i < l->body_count; i++, blist++)
	    free_command_lines (blist);
	}
      next = l->next;
      xfree (l->line);
      xfree (l);
      l = next;
    }
  *lptr = NULL;
}

static void
do_free_command_lines_cleanup (void *arg)
{
  free_command_lines ((struct command_line **) arg);
}

struct cleanup *
make_cleanup_free_command_lines (struct command_line **arg)
{
  return make_cleanup (do_free_command_lines_cleanup, arg);
}

struct command_line *
copy_command_lines (struct command_line *cmds)
{
  struct command_line *result = NULL;

  if (cmds)
    {
      result = XNEW (struct command_line);

      result->next = copy_command_lines (cmds->next);
      result->line = xstrdup (cmds->line);
      result->control_type = cmds->control_type;
      result->body_count = cmds->body_count;
      if (cmds->body_count > 0)
        {
          int i;

          result->body_list = XNEWVEC (struct command_line *, cmds->body_count);

          for (i = 0; i < cmds->body_count; i++)
            result->body_list[i] = copy_command_lines (cmds->body_list[i]);
        }
      else
        result->body_list = NULL;
    }

  return result;
}

/* Validate that *COMNAME is a valid name for a command.  Return the
   containing command list, in case it starts with a prefix command.
   The prefix must already exist.  *COMNAME is advanced to point after
   any prefix, and a NUL character overwrites the space after the
   prefix.  */

static struct cmd_list_element **
validate_comname (char **comname)
{
  struct cmd_list_element **list = &cmdlist;
  char *p, *last_word;

  if (*comname == 0)
    error_no_arg (_("name of command to define"));

  /* Find the last word of the argument.  */
  p = *comname + strlen (*comname);
  while (p > *comname && isspace (p[-1]))
    p--;
  while (p > *comname && !isspace (p[-1]))
    p--;
  last_word = p;

  /* Find the corresponding command list.  */
  if (last_word != *comname)
    {
      struct cmd_list_element *c;
      char saved_char;
      const char *tem = *comname;

      /* Separate the prefix and the command.  */
      saved_char = last_word[-1];
      last_word[-1] = '\0';

      c = lookup_cmd (&tem, cmdlist, "", 0, 1);
      if (c->prefixlist == NULL)
	error (_("\"%s\" is not a prefix command."), *comname);

      list = c->prefixlist;
      last_word[-1] = saved_char;
      *comname = last_word;
    }

  p = *comname;
  while (*p)
    {
      if (!isalnum (*p) && *p != '-' && *p != '_')
	error (_("Junk in argument list: \"%s\""), p);
      p++;
    }

  return list;
}

/* This is just a placeholder in the command data structures.  */
static void
user_defined_command (char *ignore, int from_tty)
{
}

static void
define_command (char *comname, int from_tty)
{
#define MAX_TMPBUF 128   
  enum cmd_hook_type
    {
      CMD_NO_HOOK = 0,
      CMD_PRE_HOOK,
      CMD_POST_HOOK
    };
  struct command_line *cmds;
  struct cmd_list_element *c, *newc, *hookc = 0, **list;
  char *tem, *comfull;
  const char *tem_c;
  char tmpbuf[MAX_TMPBUF];
  int  hook_type      = CMD_NO_HOOK;
  int  hook_name_size = 0;
   
#define	HOOK_STRING	"hook-"
#define	HOOK_LEN 5
#define HOOK_POST_STRING "hookpost-"
#define HOOK_POST_LEN    9

  comfull = comname;
  list = validate_comname (&comname);

  /* Look it up, and verify that we got an exact match.  */
  tem_c = comname;
  c = lookup_cmd (&tem_c, *list, "", -1, 1);
  if (c && strcmp (comname, c->name) != 0)
    c = 0;

  if (c)
    {
      int q;

      if (c->theclass == class_user || c->theclass == class_alias)
	q = query (_("Redefine command \"%s\"? "), c->name);
      else
	q = query (_("Really redefine built-in command \"%s\"? "), c->name);
      if (!q)
	error (_("Command \"%s\" not redefined."), c->name);
    }

  /* If this new command is a hook, then mark the command which it
     is hooking.  Note that we allow hooking `help' commands, so that
     we can hook the `stop' pseudo-command.  */

  if (!strncmp (comname, HOOK_STRING, HOOK_LEN))
    {
       hook_type      = CMD_PRE_HOOK;
       hook_name_size = HOOK_LEN;
    }
  else if (!strncmp (comname, HOOK_POST_STRING, HOOK_POST_LEN))
    {
      hook_type      = CMD_POST_HOOK;
      hook_name_size = HOOK_POST_LEN;
    }
   
  if (hook_type != CMD_NO_HOOK)
    {
      /* Look up cmd it hooks, and verify that we got an exact match.  */
      tem_c = comname + hook_name_size;
      hookc = lookup_cmd (&tem_c, *list, "", -1, 0);
      if (hookc && strcmp (comname + hook_name_size, hookc->name) != 0)
	hookc = 0;
      if (!hookc)
	{
	  warning (_("Your new `%s' command does not "
		     "hook any existing command."),
		   comfull);
	  if (!query (_("Proceed? ")))
	    error (_("Not confirmed."));
	}
    }

  comname = xstrdup (comname);

  /* If the rest of the commands will be case insensitive, this one
     should behave in the same manner.  */
  for (tem = comname; *tem; tem++)
    if (isupper (*tem))
      *tem = tolower (*tem);

  xsnprintf (tmpbuf, sizeof (tmpbuf),
	     "Type commands for definition of \"%s\".", comfull);
  cmds = read_command_lines (tmpbuf, from_tty, 1, 0, 0);

  if (c && c->theclass == class_user)
    free_command_lines (&c->user_commands);

  newc = add_cmd (comname, class_user, user_defined_command,
		  (c && c->theclass == class_user)
		  ? c->doc : xstrdup ("User-defined."), list);
  newc->user_commands = cmds;

  /* If this new command is a hook, then mark both commands as being
     tied.  */
  if (hookc)
    {
      switch (hook_type)
        {
        case CMD_PRE_HOOK:
          hookc->hook_pre  = newc;  /* Target gets hooked.  */
          newc->hookee_pre = hookc; /* We are marked as hooking target cmd.  */
          break;
        case CMD_POST_HOOK:
          hookc->hook_post  = newc;  /* Target gets hooked.  */
          newc->hookee_post = hookc; /* We are marked as hooking
					target cmd.  */
          break;
        default:
          /* Should never come here as hookc would be 0.  */
	  internal_error (__FILE__, __LINE__, _("bad switch"));
        }
    }
}

static void
document_command (char *comname, int from_tty)
{
  struct command_line *doclines;
  struct cmd_list_element *c, **list;
  const char *tem;
  char *comfull;
  char tmpbuf[128];

  comfull = comname;
  list = validate_comname (&comname);

  tem = comname;
  c = lookup_cmd (&tem, *list, "", 0, 1);

  if (c->theclass != class_user)
    error (_("Command \"%s\" is built-in."), comfull);

  xsnprintf (tmpbuf, sizeof (tmpbuf), "Type documentation for \"%s\".",
	     comfull);
  doclines = read_command_lines (tmpbuf, from_tty, 0, 0, 0);

  if (c->doc)
    xfree ((char *) c->doc);

  {
    struct command_line *cl1;
    int len = 0;
    char *doc;

    for (cl1 = doclines; cl1; cl1 = cl1->next)
      len += strlen (cl1->line) + 1;

    doc = (char *) xmalloc (len + 1);
    *doc = 0;

    for (cl1 = doclines; cl1; cl1 = cl1->next)
      {
	strcat (doc, cl1->line);
	if (cl1->next)
	  strcat (doc, "\n");
      }

    c->doc = doc;
  }

  free_command_lines (&doclines);
}

struct source_cleanup_lines_args
{
  int old_line;
  const char *old_file;
};

static void
source_cleanup_lines (void *args)
{
  struct source_cleanup_lines_args *p =
    (struct source_cleanup_lines_args *) args;

  source_line_number = p->old_line;
  source_file_name = p->old_file;
}

/* Used to implement source_command.  */

void
script_from_file (FILE *stream, const char *file)
{
  struct cleanup *old_cleanups;
  struct source_cleanup_lines_args old_lines;

  if (stream == NULL)
    internal_error (__FILE__, __LINE__, _("called with NULL file pointer!"));

  old_lines.old_line = source_line_number;
  old_lines.old_file = source_file_name;
  old_cleanups = make_cleanup (source_cleanup_lines, &old_lines);
  source_line_number = 0;
  source_file_name = file;

  make_cleanup_restore_integer (&current_ui->async);
  current_ui->async = 0;

  {

    TRY
      {
	read_command_file (stream);
      }
    CATCH (e, RETURN_MASK_ERROR)
      {
	/* Re-throw the error, but with the file name information
	   prepended.  */
	throw_error (e.error,
		     _("%s:%d: Error in sourced command file:\n%s"),
		     source_file_name, source_line_number, e.message);
      }
    END_CATCH
  }

  do_cleanups (old_cleanups);
}

/* Print the definition of user command C to STREAM.  Or, if C is a
   prefix command, show the definitions of all user commands under C
   (recursively).  PREFIX and NAME combined are the name of the
   current command.  */
void
show_user_1 (struct cmd_list_element *c, const char *prefix, const char *name,
	     struct ui_file *stream)
{
  struct command_line *cmdlines;

  if (c->prefixlist != NULL)
    {
      const char *prefixname = c->prefixname;

      for (c = *c->prefixlist; c != NULL; c = c->next)
	if (c->theclass == class_user || c->prefixlist != NULL)
	  show_user_1 (c, prefixname, c->name, gdb_stdout);
      return;
    }

  cmdlines = c->user_commands;
  fprintf_filtered (stream, "User command \"%s%s\":\n", prefix, name);

  if (!cmdlines)
    return;
  print_command_lines (current_uiout, cmdlines, 1);
  fputs_filtered ("\n", stream);
}



initialize_file_ftype _initialize_cli_script;

void
_initialize_cli_script (void)
{
  add_com ("document", class_support, document_command, _("\
Document a user-defined command.\n\
Give command name as argument.  Give documentation on following lines.\n\
End with a line of just \"end\"."));
  add_com ("define", class_support, define_command, _("\
Define a new command name.  Command name is argument.\n\
Definition appears on following lines, one command per line.\n\
End with a line of just \"end\".\n\
Use the \"document\" command to give documentation for the new command.\n\
Commands defined in this way may have up to ten arguments."));

  add_com ("while", class_support, while_command, _("\
Execute nested commands WHILE the conditional expression is non zero.\n\
The conditional expression must follow the word `while' and must in turn be\n\
followed by a new line.  The nested commands must be entered one per line,\n\
and should be terminated by the word `end'."));

  add_com ("if", class_support, if_command, _("\
Execute nested commands once IF the conditional expression is non zero.\n\
The conditional expression must follow the word `if' and must in turn be\n\
followed by a new line.  The nested commands must be entered one per line,\n\
and should be terminated by the word 'else' or `end'.  If an else clause\n\
is used, the same rules apply to its nested commands as to the first ones."));
}
