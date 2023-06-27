#include <windows.h>

#if _WIN64
#include <polyhook2/Detour/x64Detour.hpp>
#define HUDetour PLH::x64Detour
#define HOOKUTILS_JUMP_SIZE 6 + 8
#else
#include <polyhook2/Detour/x86Detour.hpp>
#define HUDetour PLH::x86Detour
#define HOOKUTILS_JUMP_SIZE 5
#endif

#define HUDefineHook(ret, cconv, name, ...)                                \
  typedef ret(cconv *Type_##name)(__VA_ARGS__);                                       \
  Type_##name orig_##name;                                                     \
  uint64_t tramp_##name;                                                       \
  HUDetour *det_##name;                                                        \
  ret cconv name(__VA_ARGS__)
#define HUOriginal(name) PLH::FnCast(tramp_##name, orig_##name)
#define HUAttachHook(name, addr)                                               \
  orig_##name = (Type_##name)(addr);                                           \
  det_##name =                                                                 \
      new HUDetour((uintptr_t)orig_##name, (uintptr_t)&name, &tramp_##name);   \
  det_##name->hook();
// TODO: detach

namespace HookUtils {
uintptr_t FollowPtrs(uintptr_t addr, std::vector<unsigned int> offsets);
class Asm {
  struct OldBytes {
    byte Bytes[HOOKUTILS_JUMP_SIZE];
  };

public:
  std::map<uintptr_t, OldBytes> Hooks = {};

  // TODO: test x64
  int Hook(uintptr_t loc, void *func);
  int Unhook(uintptr_t loc);
};
} // namespace HookUtils
