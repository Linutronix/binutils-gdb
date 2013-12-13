/* THIS FILE IS GENERATED -*- buffer-read-only: t -*- */
/* vi:set ro: */

/* To regenerate this file, run:*/
/*      make-target-delegates target.h > target-delegates.c */
static void
delegate_detach (struct target_ops *self, const char *arg1, int arg2)
{
  self = self->beneath;
  self->to_detach (self, arg1, arg2);
}

static void
tdefault_detach (struct target_ops *self, const char *arg1, int arg2)
{
}

static void
delegate_resume (struct target_ops *self, ptid_t arg1, int arg2, enum gdb_signal arg3)
{
  self = self->beneath;
  self->to_resume (self, arg1, arg2, arg3);
}

static void
tdefault_resume (struct target_ops *self, ptid_t arg1, int arg2, enum gdb_signal arg3)
{
  noprocess ();
}

static ptid_t
delegate_wait (struct target_ops *self, ptid_t arg1, struct target_waitstatus *arg2, int arg3)
{
  self = self->beneath;
  return self->to_wait (self, arg1, arg2, arg3);
}

static ptid_t
tdefault_wait (struct target_ops *self, ptid_t arg1, struct target_waitstatus *arg2, int arg3)
{
  noprocess ();
}

static void
delegate_store_registers (struct target_ops *self, struct regcache *arg1, int arg2)
{
  self = self->beneath;
  self->to_store_registers (self, arg1, arg2);
}

static void
tdefault_store_registers (struct target_ops *self, struct regcache *arg1, int arg2)
{
  noprocess ();
}

static int
delegate_insert_breakpoint (struct target_ops *self, struct gdbarch *arg1, struct bp_target_info *arg2)
{
  self = self->beneath;
  return self->to_insert_breakpoint (self, arg1, arg2);
}

static int
delegate_remove_breakpoint (struct target_ops *self, struct gdbarch *arg1, struct bp_target_info *arg2)
{
  self = self->beneath;
  return self->to_remove_breakpoint (self, arg1, arg2);
}

static int
delegate_stopped_by_watchpoint (struct target_ops *self)
{
  self = self->beneath;
  return self->to_stopped_by_watchpoint (self);
}

static int
tdefault_stopped_by_watchpoint (struct target_ops *self)
{
  return 0;
}

static int
delegate_stopped_data_address (struct target_ops *self, CORE_ADDR *arg1)
{
  self = self->beneath;
  return self->to_stopped_data_address (self, arg1);
}

static int
tdefault_stopped_data_address (struct target_ops *self, CORE_ADDR *arg1)
{
  return 0;
}

static int
delegate_can_async_p (struct target_ops *self)
{
  self = self->beneath;
  return self->to_can_async_p (self);
}

static int
delegate_is_async_p (struct target_ops *self)
{
  self = self->beneath;
  return self->to_is_async_p (self);
}

static void
delegate_async (struct target_ops *self, async_callback_ftype *arg1, void *arg2)
{
  self = self->beneath;
  self->to_async (self, arg1, arg2);
}

static void
tdefault_async (struct target_ops *self, async_callback_ftype *arg1, void *arg2)
{
  tcomplain ();
}

static enum target_xfer_status 
delegate_xfer_partial (struct target_ops *self, enum target_object  arg1, const char *arg2, gdb_byte *arg3, const gdb_byte *arg4, ULONGEST arg5, ULONGEST arg6, ULONGEST *arg7)
{
  self = self->beneath;
  return self->to_xfer_partial (self, arg1, arg2, arg3, arg4, arg5, arg6, arg7);
}

static enum target_xfer_status 
tdefault_xfer_partial (struct target_ops *self, enum target_object  arg1, const char *arg2, gdb_byte *arg3, const gdb_byte *arg4, ULONGEST arg5, ULONGEST arg6, ULONGEST *arg7)
{
  return TARGET_XFER_E_IO;
}

static int
delegate_supports_btrace (struct target_ops *self)
{
  self = self->beneath;
  return self->to_supports_btrace (self);
}

static int
tdefault_supports_btrace (struct target_ops *self)
{
  return 0;
}

static void
install_delegators (struct target_ops *ops)
{
  if (ops->to_detach == NULL)
    ops->to_detach = delegate_detach;
  if (ops->to_resume == NULL)
    ops->to_resume = delegate_resume;
  if (ops->to_wait == NULL)
    ops->to_wait = delegate_wait;
  if (ops->to_store_registers == NULL)
    ops->to_store_registers = delegate_store_registers;
  if (ops->to_insert_breakpoint == NULL)
    ops->to_insert_breakpoint = delegate_insert_breakpoint;
  if (ops->to_remove_breakpoint == NULL)
    ops->to_remove_breakpoint = delegate_remove_breakpoint;
  if (ops->to_stopped_by_watchpoint == NULL)
    ops->to_stopped_by_watchpoint = delegate_stopped_by_watchpoint;
  if (ops->to_stopped_data_address == NULL)
    ops->to_stopped_data_address = delegate_stopped_data_address;
  if (ops->to_can_async_p == NULL)
    ops->to_can_async_p = delegate_can_async_p;
  if (ops->to_is_async_p == NULL)
    ops->to_is_async_p = delegate_is_async_p;
  if (ops->to_async == NULL)
    ops->to_async = delegate_async;
  if (ops->to_xfer_partial == NULL)
    ops->to_xfer_partial = delegate_xfer_partial;
  if (ops->to_supports_btrace == NULL)
    ops->to_supports_btrace = delegate_supports_btrace;
}

static void
install_dummy_methods (struct target_ops *ops)
{
  ops->to_detach = tdefault_detach;
  ops->to_resume = tdefault_resume;
  ops->to_wait = tdefault_wait;
  ops->to_store_registers = tdefault_store_registers;
  ops->to_insert_breakpoint = memory_insert_breakpoint;
  ops->to_remove_breakpoint = memory_remove_breakpoint;
  ops->to_stopped_by_watchpoint = tdefault_stopped_by_watchpoint;
  ops->to_stopped_data_address = tdefault_stopped_data_address;
  ops->to_can_async_p = find_default_can_async_p;
  ops->to_is_async_p = find_default_is_async_p;
  ops->to_async = tdefault_async;
  ops->to_xfer_partial = tdefault_xfer_partial;
  ops->to_supports_btrace = tdefault_supports_btrace;
}