#if defined _WIN32
#include <windows.h>
#else
#include <link.h>
#include <sys/mman.h>
#include <unistd.h>
#endif
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <ISmmPlugin.h>

#ifndef LOBBYFIX_DATE
#define LOBBYFIX_DATE "2026-11-14"
#endif

#if !defined _WIN32
// Built without a C++ runtime (-nostdlib++); these are the only pieces the ISmmPlugin vtable needs.
extern "C" void __cxa_pure_virtual()
{
	abort();
}
void operator delete(void *p) noexcept
{
	free(p);
}
void operator delete(void *p, size_t) noexcept
{
	free(p);
}
#endif

class LobbyFixPlugin : public ISmmPlugin
{
public:
	bool Load(PluginId id, ISmmAPI *ismm, char *error, size_t maxlen, bool late) override;
	bool Unload(char *error, size_t maxlen) override;
	bool Pause(char *error, size_t maxlen) override;
	bool Unpause(char *error, size_t maxlen) override;
	void AllPluginsLoaded() override {}

	const char *GetAuthor() override { return "libxcnya.so"; }
	const char *GetName() override { return "LobbyFix"; }
	const char *GetDescription() override { return "Lets CS:GO legacy clients direct-connect without the GC lobby reservation"; }
	const char *GetURL() override { return ""; }
	const char *GetLicense() override { return "Public Domain"; }
	const char *GetVersion() override { return "1.1.0"; }
	const char *GetDate() override { return LOBBYFIX_DATE; }
	const char *GetLogTag() override { return "LOBBYFIX"; }
};

LobbyFixPlugin g_LobbyFix;
PLUGIN_EXPOSE(LobbyFixPlugin, g_LobbyFix);
PLUGIN_GLOBALVARS();

namespace
{
struct CodePatch
{
	const char *name;
	uint8_t *addr;
	size_t len;
	uint8_t orig[8];
	uint8_t repl[8];
	bool applied;
};

struct EngineModule
{
	uint8_t *base;
	uintptr_t lo;
	uintptr_t hi;
	uint8_t *code;
	size_t codeSize;
#if !defined _WIN32
	int codeProt;
#endif
};

const size_t kMaxPatches = 8;
CodePatch g_patches[kMaxPatches];
size_t g_numPatches = 0;
EngineModule g_engine;

bool ParseSig(const char *sig, uint8_t *bytes, bool *mask, size_t cap, size_t *outLen)
{
	size_t n = 0;
	for (const char *p = sig; *p;)
	{
		if (*p == ' ')
		{
			p++;
			continue;
		}
		if (n >= cap)
			return false;
		if (p[0] == '?' && p[1] == '?')
		{
			bytes[n] = 0;
			mask[n] = false;
		}
		else
		{
			char hex[3] = {p[0], p[1], 0};
			bytes[n] = (uint8_t)strtoul(hex, nullptr, 16);
			mask[n] = true;
		}
		n++;
		p += 2;
	}
	*outLen = n;
	return n > 0;
}

int FindUnique(const char *sig, uint8_t **out)
{
	uint8_t bytes[256];
	bool mask[256];
	size_t len = 0;
	if (!ParseSig(sig, bytes, mask, sizeof(bytes), &len))
		return -1;

	int hits = 0;
	for (size_t i = 0; i + len <= g_engine.codeSize; i++)
	{
		const uint8_t *cur = g_engine.code + i;
		size_t j = 0;
		while (j < len && (!mask[j] || cur[j] == bytes[j]))
			j++;
		if (j == len && hits++ == 0)
			*out = const_cast<uint8_t *>(cur);
	}
	return hits;
}

bool InEngine(uintptr_t p, size_t len)
{
	return p >= g_engine.lo && p + len <= g_engine.hi;
}

bool PointsToString(uint8_t *immAddr, const char *expect)
{
	uint32_t imm;
	memcpy(&imm, immAddr, 4);
	size_t slen = strlen(expect);
	return InEngine(imm, slen + 1) && memcmp((const void *)(uintptr_t)imm, expect, slen + 1) == 0;
}

void AddPatch(const char *name, uint8_t *addr, const void *repl, size_t len)
{
	CodePatch &p = g_patches[g_numPatches++];
	p.name = name;
	p.addr = addr;
	p.len = len;
	memcpy(p.orig, addr, len);
	memcpy(p.repl, repl, len);
	p.applied = false;
}

bool FindSite(const char *name, const char *sig, uint8_t **out, char *error, size_t maxlen)
{
	int hits = FindUnique(sig, out);
	if (hits != 1)
	{
		g_SMAPI->Format(error, maxlen, "%s signature matched %d times (expected 1)", name, hits);
		return false;
	}
	return true;
}

/*
 * Both builds: the "hibernation grace reservation" in CBaseServer::ReplyChallenge. When a challenge
 * carries a reservation cookie ("connect0x<cookie>", e.g. a client using the main menu's reconnect after
 * leaving a match) and the server isn't reserved yet, the server reserves itself for that cookie
 * ("[R] Connect from ...") and reloads the map. With the lobby id patched to 0 the client's connect never
 * carries the cookie, so it is rejected with #Valve_Reject_Reserved_For_Lobby, and so is every retry.
 * The reservation step becomes a jump to where the code goes for sv_lan or an already reserved server:
 * the target of the guard's IsReserved() jne.
 */
bool AddGraceReservationPatch(uint8_t *guard, size_t reservedJneOff, uint8_t *reserve, char *error, size_t maxlen)
{
	uint8_t *jne = guard + reservedJneOff;
	if (jne[0] != 0x0F || jne[1] != 0x85)
	{
		g_SMAPI->Format(error, maxlen, "grace reservation guard has no jne at +0x%X", (unsigned)reservedJneOff);
		return false;
	}
	int32_t rel;
	memcpy(&rel, jne + 2, 4);
	uint8_t *skip = jne + 6 + rel;
	size_t distance = skip > reserve ? (size_t)(skip - reserve) : (size_t)(reserve - skip);
	if (reserve <= guard || reserve - guard > 0x400 || skip == reserve || distance > 0x1000 ||
		!InEngine((uintptr_t)skip, 1))
	{
		g_SMAPI->Format(error, maxlen, "grace reservation sites are not where expected");
		return false;
	}
	uint8_t jmp[6] = {0xE9, 0, 0, 0, 0, 0x90}; // jmp skip; nop
	int32_t jrel = (int32_t)(skip - (reserve + 5));
	memcpy(jmp + 1, &jrel, 4);
	AddPatch("grace reservation", reserve, jmp, sizeof(jmp));
	return true;
}

#if defined _WIN32

bool LocateEngine(char *error, size_t maxlen)
{
	HMODULE mod = GetModuleHandleA("engine.dll");
	if (!mod)
	{
		g_SMAPI->Format(error, maxlen, "engine.dll is not loaded");
		return false;
	}
	g_engine.base = (uint8_t *)mod;
	auto dos = (IMAGE_DOS_HEADER *)g_engine.base;
	auto nt = (IMAGE_NT_HEADERS *)(g_engine.base + dos->e_lfanew);
	g_engine.lo = (uintptr_t)g_engine.base;
	g_engine.hi = g_engine.lo + nt->OptionalHeader.SizeOfImage;

	auto sec = IMAGE_FIRST_SECTION(nt);
	for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
	{
		if (memcmp(sec->Name, ".text", 6) == 0)
		{
			g_engine.code = g_engine.base + sec->VirtualAddress;
			g_engine.codeSize = sec->Misc.VirtualSize;
			return true;
		}
	}
	g_SMAPI->Format(error, maxlen, "engine.dll has no .text section");
	return false;
}

bool WriteCode(uint8_t *dst, const uint8_t *src, size_t len)
{
	DWORD old;
	if (!VirtualProtect(dst, len, PAGE_EXECUTE_READWRITE, &old))
		return false;
	memcpy(dst, src, len);
	VirtualProtect(dst, len, old, &old);
	FlushInstructionCache(GetCurrentProcess(), dst, len);
	return true;
}

/*
 * MSVC build. CBaseServer::ReplyChallenge picks the lobby type ("public"/"friends") inline and
 * writes a hard-coded lobby id of -1. Clients that see a non-empty lobby type or a non-zero
 * lobby id wait for a GC reservation the legacy GC never sends; "" + 0 makes them connect directly.
 */
const char *kSigReplyChallengeLobby =
	"BE ?? ?? ?? ?? FF 50 34 85 C0 75 0B 8B 07 8B CF FF 50 74 85 C0 74 05 BE ?? ?? ?? ?? 6A 20 FF 35 "
	"?? ?? ?? ?? 8D 4C 24 28 E8 ?? ?? ?? ?? 56 8D 4C 24 24 E8 ?? ?? ?? ?? 51 6A 08 FF 74 24 40 8D 4C "
	"24 2C E8 ?? ?? ?? ?? 51 6A 20 6A FF 8D 4C 24 2C E8 ?? ?? ?? ?? 51 6A 20 6A FF 8D 4C 24 2C E8 "
	"?? ?? ?? ??";
const size_t kOffPublicImm = 0x01;
const size_t kOffFriendsImm = 0x18;
const size_t kOffLobbyIdLo = 0x4B;
const size_t kOffLobbyIdHi = 0x59;

/*
 * CBaseServer::IsExclusiveToLobbyConnections() (Steam-logged-on && sv_lan 0). MSVC only calls it
 * from ConnectClient, so forcing it to false is equivalent to patching each ConnectClient check.
 */
const char *kSigIsExclusiveToLobby =
	"8B 01 8B 40 5C FF D0 84 C0 75 01 C3 A1 ?? ?? ?? ?? B9 ?? ?? ?? ?? FF 50 34 85 C0 0F 94 C0 C3";

// Grace reservation (see AddGraceReservationPatch). MSVC inlines IsExclusiveToLobbyConnections here: the
// guard is the sv_lan check followed by the IsReserved() check.
const char *kSigGraceGuard =
	"A1 ?? ?? ?? ?? B9 ?? ?? ?? ?? FF 50 34 85 C0 0F 85 ?? ?? ?? ?? 8B 87 F0 02 00 00 0B 87 F4 02 00 00 0F 85 ?? ?? ?? ??";
const size_t kOffGraceReservedJne = 0x21;
const char *kSigGraceReserve = "8B 8F F8 02 00 00 85 C9 0F 84 ?? ?? ?? ?? 8B 01 0B 41 04 0F 84 ?? ?? ?? ??";

bool AddImmToEmptyString(const char *name, uint8_t *immAddr, const char *expect, char *error, size_t maxlen)
{
	if (!PointsToString(immAddr, expect))
	{
		g_SMAPI->Format(error, maxlen, "%s: operand does not point to \"%s\"", name, expect);
		return false;
	}
	uint32_t imm;
	memcpy(&imm, immAddr, 4);
	// The string's own terminator is an empty string that survives relocation.
	uint32_t repl = imm + (uint32_t)strlen(expect);
	AddPatch(name, immAddr, &repl, 4);
	return true;
}

bool ResolvePlatformPatches(char *error, size_t maxlen)
{
	uint8_t *reply = nullptr;
	int hits = FindUnique(kSigReplyChallengeLobby, &reply);
	if (hits != 1)
	{
		g_SMAPI->Format(error, maxlen, "ReplyChallenge lobby signature matched %d times (expected 1)", hits);
		return false;
	}
	if (!AddImmToEmptyString("lobby type public", reply + kOffPublicImm, "public", error, maxlen))
		return false;
	if (!AddImmToEmptyString("lobby type friends", reply + kOffFriendsImm, "friends", error, maxlen))
		return false;

	const uint8_t zero = 0x00;
	const size_t idOffsets[2] = {kOffLobbyIdLo, kOffLobbyIdHi};
	const char *idNames[2] = {"lobby id low", "lobby id high"};
	for (int i = 0; i < 2; i++)
	{
		size_t off = idOffsets[i];
		if (reply[off - 1] != 0x6A || reply[off] != 0xFF)
		{
			g_SMAPI->Format(error, maxlen, "lobby id push at +0x%X is not 'push -1'", (unsigned)off);
			return false;
		}
		AddPatch(idNames[i], reply + off, &zero, 1);
	}

	uint8_t *exclusive = nullptr;
	hits = FindUnique(kSigIsExclusiveToLobby, &exclusive);
	if (hits != 1)
	{
		g_SMAPI->Format(error, maxlen, "IsExclusiveToLobbyConnections signature matched %d times (expected 1)", hits);
		return false;
	}
	const uint8_t retFalse[3] = {0x32, 0xC0, 0xC3}; // xor al, al; ret
	AddPatch("IsExclusiveToLobbyConnections", exclusive, retFalse, sizeof(retFalse));

	uint8_t *guard = nullptr;
	uint8_t *reserve = nullptr;
	if (!FindSite("grace reservation guard", kSigGraceGuard, &guard, error, maxlen) ||
		!FindSite("grace reservation", kSigGraceReserve, &reserve, error, maxlen))
		return false;
	return AddGraceReservationPatch(guard, kOffGraceReservedJne, reserve, error, maxlen);
}

#else

int FindEngineCallback(struct dl_phdr_info *info, size_t, void *)
{
	const char *name = info->dlpi_name;
	size_t n = name ? strlen(name) : 0;
	if (n < 9 || strcmp(name + n - 9, "engine.so") != 0 || (n > 9 && name[n - 10] != '/'))
		return 0;

	g_engine.base = (uint8_t *)info->dlpi_addr;
	g_engine.lo = UINTPTR_MAX;
	g_engine.hi = 0;
	for (int i = 0; i < info->dlpi_phnum; i++)
	{
		const ElfW(Phdr) &ph = info->dlpi_phdr[i];
		if (ph.p_type != PT_LOAD)
			continue;
		uintptr_t start = info->dlpi_addr + ph.p_vaddr;
		uintptr_t end = start + ph.p_memsz;
		if (start < g_engine.lo)
			g_engine.lo = start;
		if (end > g_engine.hi)
			g_engine.hi = end;
		if ((ph.p_flags & PF_X) && !g_engine.code)
		{
			g_engine.code = (uint8_t *)start;
			g_engine.codeSize = ph.p_memsz;
			g_engine.codeProt = PROT_EXEC | ((ph.p_flags & PF_R) ? PROT_READ : 0) | ((ph.p_flags & PF_W) ? PROT_WRITE : 0);
		}
	}
	return 1;
}

bool LocateEngine(char *error, size_t maxlen)
{
	memset(&g_engine, 0, sizeof(g_engine));
	if (!dl_iterate_phdr(FindEngineCallback, nullptr) || !g_engine.base)
	{
		g_SMAPI->Format(error, maxlen, "engine.so is not loaded");
		return false;
	}
	if (!g_engine.code)
	{
		g_SMAPI->Format(error, maxlen, "engine.so has no executable segment");
		return false;
	}
	return true;
}

bool WriteCode(uint8_t *dst, const uint8_t *src, size_t len)
{
	uintptr_t page = (uintptr_t)sysconf(_SC_PAGESIZE);
	uintptr_t start = (uintptr_t)dst & ~(page - 1);
	size_t span = ((uintptr_t)dst + len) - start;
	if (mprotect((void *)start, span, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
		return false;
	memcpy(dst, src, len);
	mprotect((void *)start, span, g_engine.codeProt);
	return true;
}

/*
 * gcc build. Unlike MSVC, gcc does not inline CBaseServer::IsExclusiveToLobbyConnections and
 * calls it from six places, including the hibernation grace-reservation logic in ReplyChallenge.
 * To match the Windows patches, three call sites are neutralised (call -> xor eax,eax) instead of
 * patching the function body, and the grace reservation gets the same jump as on Windows; its guard's
 * call is left alone so the connect-retry and LAN-only checks behind it still run.
 */
const char *kSigReplyChallengeLobby =
	"83 EC 0C BF ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 10 84 C0 0F 85 B1 04 00 00 E8 ?? ?? ?? ?? 83 EC "
	"08 50 56 E8 ?? ?? ?? ?? 58 5A 57 56 E8 ?? ?? ?? ?? 0F B6 85 97 FB FF FF 59 5F 50 56 E8 ?? ?? ?? "
	"?? 83 C4 0C 6A FF 6A FF 56 E8 ?? ?? ?? ?? 58 5A 6A 00 56 E8 ?? ?? ?? ??";
const size_t kOffEmptyLobbyImm = 0x04;
const size_t kOffLobbyTypeCall = 0x09;
const size_t kOffLobbyIdLo = 0x45;
const size_t kOffLobbyIdHi = 0x47;

const char *kSigConnectLobbyOnly =
	"83 EC 0C 57 E8 ?? ?? ?? ?? 83 C4 10 84 C0 74 74 8B 87 F0 02 00 00 0B 87 EC 02 00 00 75 66 8B 07 "
	"8D 95 64 FF FF FF 83 EC 0C 31 F6 FF 75 14 52 68 ?? ?? ?? ?? FF B5 24 FF FF FF 57 FF 90 D4 00 00 00";
const size_t kOffConnectCall = 0x04;
const size_t kOffConnectMsgImm = 0x30;

const char *kSigCookieCheck =
	"8B B5 60 F5 FF FF 8D 85 AC F5 FF FF 83 EC 0C 89 85 64 F5 FF FF 56 E8 ?? ?? ?? ?? 83 C4 10 84 C0 "
	"0F 85 71 1A 00 00 8B 86 EC 02 00 00 8B 96 F0 02 00 00 8B B5 50 F5 FF FF 8B BD 54 F5 FF FF 89 C1 "
	"89 85 30 F5 FF FF 89 D3 89 95 34 F5 FF FF 89 F2 31 C2 89 F8 31 D8 09 C2 0F 84 E2 1F 00 00 09 D9 "
	"0F 84 DA 1F";
const size_t kOffCookieCall = 0x16;

const char *kSigGraceGuard = "83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 84 C0 0F 84 ?? ?? ?? ?? 8B 83 F0 02 00 00 0B 83 EC 02 00 00 "
							 "0F 85 ?? ?? ?? ??";
const size_t kOffGraceGuardCall = 0x04;
const size_t kOffGraceReservedJne = 0x20;
const char *kSigGraceReserve = "8B 83 F4 02 00 00 85 C0 74 ?? 8B 50 04 0B 10 0F 85 ?? ?? ?? ??";

const uint8_t kIsExclusivePrologue[] = {0x55, 0x89, 0xE5, 0x83, 0xEC, 0x08, 0x8B, 0x45, 0x08, 0x8B, 0x10, 0x8B, 0x52, 0x60};

uint8_t *CallTarget(uint8_t *call)
{
	int32_t rel;
	memcpy(&rel, call + 1, 4);
	return call + 5 + rel;
}

bool ResolvePlatformPatches(char *error, size_t maxlen)
{
	uint8_t *reply = nullptr, *connect = nullptr, *cookie = nullptr;
	if (!FindSite("ReplyChallenge lobby", kSigReplyChallengeLobby, &reply, error, maxlen) ||
		!FindSite("ConnectClient lobby-only", kSigConnectLobbyOnly, &connect, error, maxlen) ||
		!FindSite("reservation cookie check", kSigCookieCheck, &cookie, error, maxlen))
		return false;

	uint8_t *calls[3] = {reply + kOffLobbyTypeCall, connect + kOffConnectCall, cookie + kOffCookieCall};
	const char *callNames[3] = {"ReplyChallenge lobby type", "ConnectClient lobby-only", "reservation cookie check"};
	uint8_t *target = CallTarget(calls[0]);
	for (int i = 0; i < 3; i++)
	{
		if (calls[i][0] != 0xE8 || CallTarget(calls[i]) != target)
		{
			g_SMAPI->Format(error, maxlen, "%s does not call IsExclusiveToLobbyConnections", callNames[i]);
			return false;
		}
	}
	if (!InEngine((uintptr_t)target, sizeof(kIsExclusivePrologue)) ||
		memcmp(target, kIsExclusivePrologue, sizeof(kIsExclusivePrologue)) != 0)
	{
		g_SMAPI->Format(error, maxlen, "IsExclusiveToLobbyConnections prologue mismatch");
		return false;
	}

	uint32_t emptyImm;
	memcpy(&emptyImm, reply + kOffEmptyLobbyImm, 4);
	if (!InEngine(emptyImm, 1) || *(const char *)(uintptr_t)emptyImm != '\0')
	{
		g_SMAPI->Format(error, maxlen, "default lobby type is not an empty string");
		return false;
	}
	if (!PointsToString(connect + kOffConnectMsgImm, "Server only accepting connections from game lobby %s %d.\n"))
	{
		g_SMAPI->Format(error, maxlen, "ConnectClient site does not reference the lobby-only message");
		return false;
	}

	const uint8_t retFalse[5] = {0x31, 0xC0, 0x0F, 0x1F, 0x00}; // xor eax, eax; nop dword [eax]
	for (int i = 0; i < 3; i++)
		AddPatch(callNames[i], calls[i], retFalse, sizeof(retFalse));

	const uint8_t zero = 0x00;
	const size_t idOffsets[2] = {kOffLobbyIdLo, kOffLobbyIdHi};
	const char *idNames[2] = {"lobby id low", "lobby id high"};
	for (int i = 0; i < 2; i++)
	{
		size_t off = idOffsets[i];
		if (reply[off - 1] != 0x6A || reply[off] != 0xFF)
		{
			g_SMAPI->Format(error, maxlen, "lobby id push at +0x%X is not 'push -1'", (unsigned)off);
			return false;
		}
		AddPatch(idNames[i], reply + off, &zero, 1);
	}

	uint8_t *guard = nullptr, *reserve = nullptr;
	if (!FindSite("grace reservation guard", kSigGraceGuard, &guard, error, maxlen) ||
		!FindSite("grace reservation", kSigGraceReserve, &reserve, error, maxlen))
		return false;
	if (guard[kOffGraceGuardCall] != 0xE8 || CallTarget(guard + kOffGraceGuardCall) != target)
	{
		g_SMAPI->Format(error, maxlen, "grace reservation guard does not call IsExclusiveToLobbyConnections");
		return false;
	}
	return AddGraceReservationPatch(guard, kOffGraceReservedJne, reserve, error, maxlen);
}

#endif

bool ResolvePatches(char *error, size_t maxlen)
{
	g_numPatches = 0;
	if (!LocateEngine(error, maxlen))
		return false;
	return ResolvePlatformPatches(error, maxlen);
}

void RestoreAll()
{
	for (size_t i = g_numPatches; i-- > 0;)
	{
		CodePatch &p = g_patches[i];
		if (p.applied && WriteCode(p.addr, p.orig, p.len))
			p.applied = false;
	}
}

bool ApplyAll(char *error, size_t maxlen)
{
	for (size_t i = 0; i < g_numPatches; i++)
	{
		CodePatch &p = g_patches[i];
		if (p.applied)
			continue;
		if (!WriteCode(p.addr, p.repl, p.len))
		{
			RestoreAll();
			g_SMAPI->Format(error, maxlen, "failed to make engine code writable while patching %s", p.name);
			return false;
		}
		p.applied = true;
	}
	return true;
}
} // namespace

bool LobbyFixPlugin::Load(PluginId id, ISmmAPI *ismm, char *error, size_t maxlen, bool late)
{
	PLUGIN_SAVEVARS();

	if (!ResolvePatches(error, maxlen) || !ApplyAll(error, maxlen))
		return false;

	for (size_t i = 0; i < g_numPatches; i++)
		META_CONPRINTF("[LobbyFix] patched %s at engine+0x%X\n", g_patches[i].name,
			(unsigned)(g_patches[i].addr - g_engine.base));
	return true;
}

bool LobbyFixPlugin::Unload(char *error, size_t maxlen)
{
	RestoreAll();
	META_CONPRINTF("[LobbyFix] restored original engine code\n");
	return true;
}

bool LobbyFixPlugin::Pause(char *error, size_t maxlen)
{
	RestoreAll();
	return true;
}

bool LobbyFixPlugin::Unpause(char *error, size_t maxlen)
{
	return ApplyAll(error, maxlen);
}
