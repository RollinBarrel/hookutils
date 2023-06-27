#include "hookutils.h"

namespace HookUtils {
uintptr_t FollowPtrs(uintptr_t addr, std::vector<unsigned int> offsets) {
  for (unsigned int i = 0; i < offsets.size(); ++i) {
    if (*(uintptr_t *)addr == 0)
      return NULL;
    addr = *(uintptr_t *)addr;
    addr += offsets[i];
  }
  return addr;
}

int Asm::Hook(uintptr_t loc, void *func) {
  DWORD prot;
  VirtualProtect((void *)loc, HOOKUTILS_JUMP_SIZE, PAGE_EXECUTE_READWRITE,
                 &prot);
  uintptr_t rel_jump = ((uintptr_t)func - loc) - HOOKUTILS_JUMP_SIZE;
  OldBytes old_bytes;
  memcpy(old_bytes.Bytes, (void *)loc, HOOKUTILS_JUMP_SIZE);
  Hooks.insert_or_assign(loc, old_bytes);
#if _WIN64
  *(WORD *)loc = 0xFF25;
  *(uint32_t *)(loc + 2) = 0;
  *(uintptr_t *)(loc + 6) = rel_jump;
#else
  *(byte *)loc = 0xE9;
  *(uintptr_t *)(loc + 1) = rel_jump;
#endif
  VirtualProtect((void *)loc, HOOKUTILS_JUMP_SIZE, prot, &prot);

  return 0;
}

int Asm::Unhook(uintptr_t loc) {
  DWORD prot;
  VirtualProtect((void *)loc, HOOKUTILS_JUMP_SIZE, PAGE_EXECUTE_READWRITE,
                 &prot);
  memcpy((void *)loc, Hooks[loc].Bytes, HOOKUTILS_JUMP_SIZE);
  VirtualProtect((void *)loc, HOOKUTILS_JUMP_SIZE, prot, &prot);
  Hooks.erase(loc);

  return 0;
}
} // namespace HookUtils