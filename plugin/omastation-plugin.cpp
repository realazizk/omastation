// omastation's Hyprland plugin:
// 1. protected windows (no_screen_share) are visible in omastation's own captures
//    of its RDP outputs, and stay hidden in every other capture;
// 2. absolute pointer motion moves the hardware cursor;
// 3. RDP outputs' own frames leave out the software cursor (the client draws it);
// 4. `hyprctl omastation-cursor` reports the cursor image's scale, hotspot and visibility;
// 5. capturing a window whose monitor is gone fails instead of crashing Hyprland.
// It only loads into the Hyprland build it was compiled for; a hook that cannot
// be installed is skipped.

#include <hyprland/src/plugins/PluginAPI.hpp>
#include <hyprland/src/managers/screenshare/ScreenshareManager.hpp>
#include <hyprland/src/pointer/PointerManager.hpp>
#include <hyprland/src/protocols/core/Compositor.hpp>
#include <hyprland/src/protocols/core/Seat.hpp>
#include <hyprland/src/render/Texture.hpp>
#include <hyprland/src/desktop/view/WLSurface.hpp>
#include <hyprland/src/desktop/view/Window.hpp>
#include <hyprland/src/desktop/view/LayerSurface.hpp>
#include <hyprland/src/desktop/state/WindowState.hpp>
#include <hyprland/src/desktop/state/LayerState.hpp>
#include <hyprland/src/output/Monitor.hpp>
#include <hyprland/src/helpers/MiscFunctions.hpp>
#include <hyprland/src/debug/log/Logger.hpp>

#include <cxxabi.h>
#include <elf.h>
#include <link.h>
#include <sys/stat.h>

#include <algorithm>
#include <filesystem>
#include <cstdlib>
#include <cstring>
#include <format>
#include <string>
#include <string_view>
#include <vector>

#ifndef OMASTATION_HYPRLAND_BUILD_ID
#error "build with omastation-plugin-build: it passes the build ID of the Hyprland it builds for"
#endif

// Only this binary's captures see protected windows.
static constexpr const char* OMASTATION_BINARY = "/usr/bin/omastation";

static HANDLE g_handle = nullptr;

// Private members, reached through explicit instantiation ([temp.spec.general]).

template <typename Tag, auto Member>
struct SPrivate {
    friend constexpr auto privateMember(Tag) {
        return Member;
    }
};

struct SFrameSession {
    friend constexpr auto privateMember(SFrameSession);
};
struct SSessionClient {
    friend constexpr auto privateMember(SSessionClient);
};
struct SMonitorStates {
    friend constexpr auto privateMember(SMonitorStates);
};
struct SOnCursorMoved {
    friend constexpr auto privateMember(SOnCursorMoved);
};
struct SManagedSessions {
    friend constexpr auto privateMember(SManagedSessions);
};

template struct SPrivate<SFrameSession, &Screenshare::CScreenshareFrame::m_session>;
template struct SPrivate<SSessionClient, &Screenshare::CScreenshareSession::m_client>;
template struct SPrivate<SMonitorStates, &Pointer::CPointerManager::m_monitorStates>;
template struct SPrivate<SOnCursorMoved, &Pointer::CPointerManager::onCursorMoved>;
template struct SPrivate<SManagedSessions, &Screenshare::CScreenshareManager::m_managedSessions>;

// ---- protected windows ----

namespace Protected {

    // omastation's outputs: RDP-1, RDP-2, ...
    static bool isRdpOutput(const std::string& name) {
        if (!name.starts_with("RDP-") || name.size() == 4)
            return false;
        return std::ranges::all_of(name.substr(4), [](char c) { return c >= '0' && c <= '9'; });
    }

    // The client is OMASTATION_BINARY: same path and same file (device and inode).
    static bool isOmastation(wl_client* client) {
        if (!client)
            return false;
        pid_t pid = 0;
        wl_client_get_credentials(client, &pid, nullptr, nullptr);
        if (pid <= 0)
            return false;
        const auto EXE = binaryNameForWlClient(client);
        if (!EXE || *EXE != OMASTATION_BINARY)
            return false;
        struct stat running, installed;
        if (stat(std::format("/proc/{}/exe", pid).c_str(), &running) != 0 || stat(OMASTATION_BINARY, &installed) != 0)
            return false;
        return running.st_dev == installed.st_dev && running.st_ino == installed.st_ino;
    }

    static bool exempt(Screenshare::CScreenshareFrame* frame) noexcept {
        try {
            // Owned by a unique pointer: used directly.
            const auto* session = (frame->*privateMember(SFrameSession{})).get();
            if (!session)
                return false;
            const auto MONITOR = session->monitor(); // a window capture: the window's output
            if (!MONITOR || !isRdpOutput(MONITOR->m_name))
                return false;
            return isOmastation(session->*privateMember(SSessionClient{}));
        } catch (...) { return false; }
    }

    // Lifts no_screen_share from every window and layer for its lifetime, then
    // restores each one exactly (at setprop priority).
    class CLift {
      public:
        CLift() noexcept {
            try {
                for (const auto& w : Desktop::windowState()->windows()) {
                    if (w && w->m_ruleApplicator)
                        lift(w->m_ruleApplicator->noScreenShare(), w, nullptr);
                }
                for (const auto& l : Desktop::layerState()->layers()) {
                    if (l && l->m_ruleApplicator)
                        lift(l->m_ruleApplicator->noScreenShare(), nullptr, l);
                }
            } catch (...) { restore(); }
        }
        ~CLift() {
            restore();
        }
        CLift(const CLift&)            = delete;
        CLift& operator=(const CLift&) = delete;

      private:
        using CVar = Desktop::Types::COverridableVar<bool>;
        struct SLifted {
            CVar*     var;
            CVar      saved;
            PHLWINDOW window; // kept alive while lifted
            PHLLS     layer;
        };
        std::vector<SLifted> m_lifted;

        void                 lift(CVar& var, PHLWINDOW w, PHLLS l) {
            if (!var.valueOrDefault())
                return;
            m_lifted.push_back({&var, var, std::move(w), std::move(l)});
            var.set(false, Desktop::Types::PRIORITY_SET_PROP);
        }

        void restore() noexcept {
            for (auto& e : m_lifted) {
                try {
                    if (e.saved.hasValue() && e.saved.getPriority() == Desktop::Types::PRIORITY_SET_PROP)
                        e.var->set(e.saved.value(), Desktop::Types::PRIORITY_SET_PROP);
                    else
                        e.var->unset(Desktop::Types::PRIORITY_SET_PROP);
                } catch (...) {}
            }
            m_lifted.clear();
        }
    };

    static CFunctionHook* g_render      = nullptr;
    static CFunctionHook* g_storeTempFB = nullptr;

    using FFrameMethod = void (*)(void*);

    static void hkRender(void* frame) {
        const auto ORIGINAL = rc<FFrameMethod>(g_render->m_original);
        if (!exempt(sc<Screenshare::CScreenshareFrame*>(frame)))
            return ORIGINAL(frame);
        CLift lift;
        ORIGINAL(frame);
    }

    static void hkStoreTempFB(void* frame) {
        const auto ORIGINAL = rc<FFrameMethod>(g_storeTempFB->m_original);
        if (!exempt(sc<Screenshare::CScreenshareFrame*>(frame)))
            return ORIGINAL(frame);
        CLift lift;
        ORIGINAL(frame);
    }
}

// ---- absolute motion moves the hardware cursor ----

namespace Cursor {

    static CFunctionHook* g_warpAbsolute = nullptr;

    using FWarpAbsolute = void (*)(void*, Vector2D, SP<IHID>);

    static void hkWarpAbsolute(void* thisptr, Vector2D abs, SP<IHID> dev) {
        auto* const PM = sc<Pointer::CPointerManager*>(thisptr);

        // Outputs entered before this motion.
        std::vector<const void*> entered;
        bool                     known = true;
        try {
            for (const auto& s : PM->*privateMember(SMonitorStates{})) {
                if (s && s->entered)
                    entered.push_back(s.get());
            }
        } catch (...) { known = false; }

        rc<FWarpAbsolute>(g_warpAbsolute->m_original)(thisptr, abs, dev);

        // The original moves the cursor before rechecking entered outputs:
        // move it again if it entered one.
        try {
            for (const auto& s : PM->*privateMember(SMonitorStates{})) {
                if (known && s && s->entered && std::ranges::find(entered, s.get()) == entered.end()) {
                    (PM->*privateMember(SOnCursorMoved{}))();
                    break;
                }
            }
        } catch (...) {}
    }
}

// ---- no software cursor in RDP outputs' own frames ----
// The RDP client draws the pointer; captures that ask for the cursor still get it.

namespace SoftwareCursor {

    static CFunctionHook* g_render = nullptr;

    using FRender = void (*)(void*, PHLMONITOR, const Time::steady_tp&, CRegion&, std::optional<Vector2D>, bool, bool);

    static void hkRenderSoftwareCursorsFor(void* thisptr, PHLMONITOR monitor, const Time::steady_tp& now, CRegion& damage, std::optional<Vector2D> overridePos, bool screencopy,
                                           bool forceRender) {
        bool rdp = false;
        try {
            rdp = monitor && monitor->m_name.starts_with("RDP-");
        } catch (...) {}
        // This frame has no cursor: a capture asking for one must render it.
        if (!rdp || screencopy)
            return rc<FRender>(g_render->m_original)(thisptr, monitor, now, damage, overridePos, screencopy, forceRender || rdp);
        // Not drawn, but the cursor surface still gets its frame event.
        try {
            const auto& IMAGE = sc<Pointer::CPointerManager*>(thisptr)->currentCursorImage();
            if (IMAGE.surface && IMAGE.surface->resource())
                IMAGE.surface->resource()->frame(now);
        } catch (...) {}
    }
}

// ---- capturing a window whose monitor is gone ----
// A window can still point at a monitor that is gone: an RDP output removed, or a
// monitor unplugged, while it was on it. Hyprland's capture session reads that
// monitor and crashes (a live window preview after an RDP session ended): the
// session is stopped instead, and the capture fails.

namespace GoneMonitor {

    static CFunctionHook* g_init       = nullptr;
    static CFunctionHook* g_getSession = nullptr;

    using FInit       = void (*)(void*);
    using FGetSession = WP<Screenshare::CScreenshareSession> (*)(void*, wl_client*, PHLWINDOW);

    static void hkInit(void* thisptr) {
        auto* const SESSION = sc<Screenshare::CScreenshareSession*>(thisptr);
        bool        gone    = false;
        try {
            gone = !SESSION->monitor();
        } catch (...) {}
        if (!gone)
            return rc<FInit>(g_init->m_original)(thisptr);
        Log::logger->log(Log::ERR, "[omastation] a client asked to capture a window whose monitor is gone: capture stopped");
        SESSION->stop();
    }

    // A session stopped while it was created did so before Hyprland listened for its
    // stop: it would be handed out for every later capture of that window. Stopped
    // sessions go first.
    static WP<Screenshare::CScreenshareSession> hkGetSession(void* thisptr, wl_client* client, PHLWINDOW window) {
        try {
            auto& managed = sc<Screenshare::CScreenshareManager*>(thisptr)->*privateMember(SManagedSessions{});
            std::erase_if(managed, [](const auto& s) { return !s || !s->m_session || !s->m_session->isActive(); });
        } catch (...) {}
        return rc<FGetSession>(g_getSession->m_original)(thisptr, client, window);
    }
}

// In the plugin description; omastation checks for it in `hyprctl plugin list`.
static constexpr const char* RDP_CURSOR_MARKER = "[rdp-frames-without-cursor]";

// ---- `hyprctl omastation-cursor` ----
// "SCALE HOTSPOT_X HOTSPOT_Y WIDTH HEIGHT SHOWN" of the current cursor image. The
// capture protocol gives the hotspot in logical units; this gives it in image
// pixels. SHOWN is 0 when Hyprland draws no visible cursor.

namespace CursorInfo {

    static SP<SHyprCtlCommand> g_command;

    // Any non-transparent pixel in a 32 bpp image with alpha in the high byte.
    static bool anyAlpha(const uint8_t* data, size_t stride, size_t w, size_t h) {
        for (size_t y = 0; y < h; ++y) {
            const auto* row = data + y * stride;
            for (size_t x = 0; x < w; ++x) {
                if (row[x * 4 + 3])
                    return true;
            }
        }
        return false;
    }

    // Whether Hyprland draws a visible cursor image; non-shm surfaces count as shown.
    static bool shown(const Pointer::CPointerManager::SCursorImage& IMAGE) {
        if (IMAGE.pBuffer) {
            const auto SHM = IMAGE.pBuffer->shm();
            if (!SHM.success || (SHM.format != DRM_FORMAT_ARGB8888 && SHM.format != DRM_FORMAT_ABGR8888) || SHM.size.x <= 0 || SHM.size.y <= 0 ||
                SHM.stride < SHM.size.x * 4)
                return true;
            // beginDataPtr's length is one row for theme buffers: use stride x height.
            auto [data, fmt, len] = IMAGE.pBuffer->beginDataPtr(0);
            const bool ANY        = !data || anyAlpha(data, sc<size_t>(SHM.stride), sc<size_t>(SHM.size.x), sc<size_t>(SHM.size.y));
            IMAGE.pBuffer->endDataPtr();
            return ANY;
        }
        const auto SURFACE = IMAGE.surface.lock();
        const auto RES     = SURFACE ? SURFACE->resource() : nullptr;
        if (!RES || !RES->m_current.texture)
            return false;
        const auto& TEX = RES->m_current.texture;
        if (!TEX->m_isSynchronous || !RES->m_role || RES->m_role->role() != SURFACE_ROLE_CURSOR ||
            (TEX->m_drmFormat != 0 && TEX->m_drmFormat != DRM_FORMAT_ARGB8888 && TEX->m_drmFormat != DRM_FORMAT_ABGR8888))
            return true;
        // The committed shm buffer (stride x height bytes).
        const auto&  PIXELS = CCursorSurfaceRole::cursorPixelData(RES);
        const size_t W = sc<size_t>(RES->m_current.bufferSize.x), H = sc<size_t>(RES->m_current.bufferSize.y);
        if (W == 0 || H == 0 || PIXELS.size() % H != 0 || PIXELS.size() / H < W * 4)
            return true;
        return anyAlpha(PIXELS.data(), PIXELS.size() / H, W, H);
    }

    static std::string answer(eHyprCtlOutputFormat, std::string) {
        try {
            const auto&  IMAGE = Pointer::mgr()->currentCursorImage();
            const double SCALE = IMAGE.scale > 0.F ? IMAGE.scale : 1.0;
            return std::format("{} {} {} {} {} {}", SCALE, IMAGE.hotspot.x * SCALE, IMAGE.hotspot.y * SCALE, IMAGE.size.x, IMAGE.size.y, shown(IMAGE) ? 1 : 0);
        } catch (...) { return "error"; }
    }
}

// ---- loading ----

// GNU build ID of the running Hyprland executable, lowercase hex.
static std::string runningBuildId() {
    std::string id;
    dl_iterate_phdr(
        [](dl_phdr_info* info, size_t, void* data) -> int {
            auto* out = sc<std::string*>(data);
            for (int i = 0; i < info->dlpi_phnum; i++) {
                const auto& ph = info->dlpi_phdr[i];
                if (ph.p_type != PT_NOTE)
                    continue;
                const auto* p   = rc<const unsigned char*>(info->dlpi_addr + ph.p_vaddr);
                const auto* end = p + ph.p_memsz;
                while (p + sizeof(ElfW(Nhdr)) <= end) {
                    ElfW(Nhdr) nh;
                    std::memcpy(&nh, p, sizeof(nh));
                    const auto* name = p + sizeof(nh);
                    const auto* desc = name + ((nh.n_namesz + 3) & ~3u);
                    if (desc + nh.n_descsz > end)
                        break;
                    if (nh.n_type == NT_GNU_BUILD_ID && nh.n_namesz == 4 && std::memcmp(name, "GNU", 4) == 0) {
                        for (size_t k = 0; k < nh.n_descsz; k++)
                            *out += std::format("{:02x}", desc[k]);
                        return 1;
                    }
                    p = desc + ((nh.n_descsz + 3) & ~3u);
                }
            }
            return 1; // the executable is the first object
        },
        &id);
    return id;
}

static std::string demangle(const std::string& mangled) {
    int         status = 0;
    char*       out    = abi::__cxa_demangle(mangled.c_str(), nullptr, nullptr, &status);
    std::string result = status == 0 && out ? out : "";
    std::free(out);
    return result;
}

// Hooks the function with exactly this demangled name, or logs and returns null.
// The name is checked against the match's own symbol: Hyprland's demangled names
// shift past a symbol it cannot resolve (inotify_init1@GLIBC_2.9 for "init"), and
// would name another match's function.
static CFunctionHook* hookOrSkip(const std::string& demangled, const void* destination, std::string_view feature) {
    const auto                  NAME = demangled.substr(0, demangled.find('('));
    const auto                  BARE = NAME.substr(NAME.rfind(':') + 1);
    std::vector<SFunctionMatch> matches;
    try {
        matches = HyprlandAPI::findFunctionsByName(g_handle, BARE);
    } catch (const std::exception& e) {
        Log::logger->log(Log::ERR, "[omastation] cannot look up {}: {}; {} is off", demangled, e.what(), feature);
        return nullptr;
    }
    for (const auto& m : matches) {
        if (demangle(m.signature) != demangled)
            continue;
        auto* hook = HyprlandAPI::createFunctionHook(g_handle, m.address, destination);
        if (hook && hook->hook())
            return hook;
        if (hook)
            HyprlandAPI::removeFunctionHook(g_handle, hook);
        Log::logger->log(Log::ERR, "[omastation] cannot hook {}: {} is off", demangled, feature);
        return nullptr;
    }
    Log::logger->log(Log::ERR, "[omastation] {} not found: {} is off", demangled, feature);
    return nullptr;
}

APICALL EXPORT std::string PLUGIN_API_VERSION() {
    return HYPRLAND_API_VERSION;
}

APICALL EXPORT PLUGIN_DESCRIPTION_INFO PLUGIN_INIT(HANDLE handle) {
    g_handle = handle;

    // Class layouts come from the headers it was built with: only that exact build will do.
    const auto RUNNING = runningBuildId();
    if (RUNNING != OMASTATION_HYPRLAND_BUILD_ID)
        throw std::runtime_error(std::format("omastation plugin: built for another Hyprland (build {}, running {}): log in again after a Hyprland update, or rebuild it "
                                             "(sudo /usr/lib/omastation/omastation-plugin-build)",
                                             OMASTATION_HYPRLAND_BUILD_ID, RUNNING.empty() ? "unknown" : RUNNING));
    if (std::string_view{__hyprland_api_get_hash()} != __hyprland_api_get_client_hash())
        throw std::runtime_error("omastation plugin: built against other Hyprland headers than this Hyprland's");
    // Hooks are found through the executable's symbols, gone once it is replaced on disk.
    std::error_code ec;
    if (const auto EXE = std::filesystem::canonical("/proc/self/exe", ec); ec || EXE.empty())
        throw std::runtime_error("omastation plugin: Hyprland's executable was replaced on disk (updated or reinstalled): log in again");

    Protected::g_render      = hookOrSkip("Screenshare::CScreenshareFrame::render()", rc<const void*>(&Protected::hkRender), "showing protected windows to omastation");
    Protected::g_storeTempFB = hookOrSkip("Screenshare::CScreenshareFrame::storeTempFB()", rc<const void*>(&Protected::hkStoreTempFB),
                                          "showing protected windows to omastation while a permission prompt is open");
    Cursor::g_warpAbsolute   = hookOrSkip("Pointer::CPointerManager::warpAbsolute(Hyprutils::Math::Vector2D, Hyprutils::Memory::CSharedPointer<IHID>)",
                                          rc<const void*>(&Cursor::hkWarpAbsolute), "the hardware cursor fix for absolute motion");
    SoftwareCursor::g_render = hookOrSkip("Pointer::CPointerManager::renderSoftwareCursorsFor(Hyprutils::Memory::CSharedPointer<Monitor::CMonitor>, "
                                          "std::chrono::time_point<std::chrono::_V2::steady_clock, std::chrono::duration<long, std::ratio<1l, 1000000000l> > > const&, "
                                          "Hyprutils::Math::CRegion&, std::optional<Hyprutils::Math::Vector2D>, bool, bool)",
                                          rc<const void*>(&SoftwareCursor::hkRenderSoftwareCursorsFor), "RDP outputs' frames without the cursor (client-drawn pointers)");
    GoneMonitor::g_init = hookOrSkip("Screenshare::CScreenshareSession::init()", rc<const void*>(&GoneMonitor::hkInit), "the fix for capturing a window whose monitor is gone");
    // Only needed with the fix: it drops the sessions the fix stops.
    if (GoneMonitor::g_init)
        GoneMonitor::g_getSession = hookOrSkip("Screenshare::CScreenshareManager::getManagedSession(wl_client*, Hyprutils::Memory::CSharedPointer<Desktop::View::CWindow>)",
                                               rc<const void*>(&GoneMonitor::hkGetSession), "capturing again a window whose monitor came back");

    if (!Protected::g_render && !Protected::g_storeTempFB && !Cursor::g_warpAbsolute && !SoftwareCursor::g_render && !GoneMonitor::g_init)
        throw std::runtime_error("omastation plugin: none of its hooks could be installed");

    try {
        CursorInfo::g_command = HyprlandAPI::registerHyprCtlCommand(g_handle, SHyprCtlCommand{.name = "omastation-cursor", .exact = true, .fn = CursorInfo::answer});
    } catch (...) { CursorInfo::g_command = nullptr; }
    if (!CursorInfo::g_command)
        Log::logger->log(Log::ERR, "[omastation] cannot register `hyprctl omastation-cursor`: RDP pointer hotspots are estimated");

    Log::logger->log(Log::INFO,
                     "[omastation] loaded for Hyprland build {}: protected windows {}, absolute motion cursor fix {}, RDP frames without the cursor {}, "
                     "capturing windows of a gone monitor fix {}",
                     RUNNING, Protected::g_render ? "on" : "off", Cursor::g_warpAbsolute ? "on" : "off", SoftwareCursor::g_render ? "on" : "off",
                     GoneMonitor::g_init ? "on" : "off");
    std::string description = "protected windows for omastation's capture of its outputs; absolute motion moves the hardware cursor";
    if (SoftwareCursor::g_render)
        description += std::string{"; RDP outputs' frames without the cursor "} + RDP_CURSOR_MARKER;
    return {"omastation", description, "omastation", "1"};
}

APICALL EXPORT void PLUGIN_EXIT() {
    // Hyprland removes the hooks itself.
}
