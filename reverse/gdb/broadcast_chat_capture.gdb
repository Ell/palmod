# Validate reflection dispatch of BroadcastChatMessage on build 24088465.
# If the EXEC THUNK (UFunction::Func, 0x6a819a0) fires when a client sends chat,
# then swapping UFunction::Func (our ChatHook) intercepts chat for real. The IMPL
# (0x720a0e0) fires regardless and lets us decode the message. Dumps + continues,
# so play is uninterrupted. Log: .palmod-lab/broadcast_chat_capture.log
set pagination off
set debuginfod enabled off
set breakpoint pending on
set logging file .palmod-lab/broadcast_chat_capture.log
set logging overwrite on
set logging enabled on

define follow_ptrs
  # $arg0 = struct pointer. Follow canonical (0x7f...) pointer fields as UTF-16 so
  # FString data (sender/message) shows up. 0x7f test avoids crashing on ints.
  set $i = 0
  while $i < 12
    set $p = *(unsigned long *)($arg0 + $i * 8)
    if ($p >> 40) == 0x7f
      printf "  field +0x%x -> 0x%lx (UTF-16):\n", $i * 8, $p
      x/40hx $p
    end
    set $i = $i + 1
  end
end

# EXEC THUNK = UFunction::Func. rsi = FFrame (Locals -> Parms -> FPalChatMessage).
break *0x6a819a0
commands
  silent
  printf "\n[THUNK 0x6a819a0 FIRED — reflection UFunction::Func dispatch CONFIRMED] rsi(FFrame)=0x%lx\n", $rsi
  follow_ptrs $rsi
  continue
end

# IMPLEMENTATION. rsi = FPalChatMessage (Sender FString @ +0x08, Message @ +0x28).
break *0x720a0e0
commands
  silent
  printf "\n[IMPL 0x720a0e0] rsi(FPalChatMessage)=0x%lx\n", $rsi
  follow_ptrs $rsi
  continue
end

run
