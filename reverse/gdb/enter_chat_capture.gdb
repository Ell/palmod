# Passive server-side chat capture for build 24088465. Launches the server under
# gdb (parent, so it may breakpoint under yama ptrace_scope=1), dumps the chat
# message struct + follows its pointer fields as UTF-16 on each hit, then
# continues so play is uninterrupted. Log: .palmod-lab/enter_chat_capture.log
# relative to the lab-root cwd.
set pagination off
set breakpoint pending on
set logging file .palmod-lab/enter_chat_capture.log
set logging overwrite on
set logging enabled on

define dump_struct_ptrs
  # $arg0 = struct pointer. Dump it, then follow only fields that are canonical
  # userspace pointers (top byte 0x7f) as UTF-16 code units (chat text is UTF-16).
  # The 0x7f test excludes packed {num,max} FString size fields, which crash a
  # raw x/ read in -batch mode.
  x/48gx $arg0
  set $i = 0
  while $i < 10
    set $p = *(unsigned long *)($arg0 + $i * 8)
    if ($p >> 40) == 0x7f
      printf "  field +0x%x -> 0x%lx (UTF-16):\n", $i * 8, $p
      x/48hx $p
    end
    set $i = $i + 1
  end
end

# PalGameStateInGame::BroadcastChatMessage(this, FPalChatMessage&): the server-side
# choke point every chat message passes through. rsi = message struct.
break *0x720a0e0
commands
  silent
  printf "\n[BroadcastChatMessage] rdi=0x%lx rsi=0x%lx\n", $rdi, $rsi
  dump_struct_ptrs $rsi
  continue
end

# EnterChat backup path: rdi=component, rsi=chat value.
break *0x74ef9e0
commands
  silent
  printf "\n[EnterChat] rdi=0x%lx rsi=0x%lx rdx=0x%lx\n", $rdi, $rsi, $rdx
  dump_struct_ptrs $rsi
  continue
end

run
