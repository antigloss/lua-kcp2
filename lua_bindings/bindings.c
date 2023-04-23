#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lauxlib.h>
#include <kcp/ikcp.h>

#ifdef RECV_BUFFER_LEN
#undef RECV_BUFFER_LEN
#endif
#define RECV_BUFFER_LEN 1024 * 1024

#define check_kcp(L, idx) *(ikcpcb**)luaL_checkudata(L, idx, "kcp2_meta")
#define check_buf(L, idx) (char*)luaL_checkudata(L, idx, "recv_buffer")

struct Callback {
    int log_handle;
    int handle;
    lua_State* L;
};

static void kcp_writelog_callback(const char* log, ikcpcb* kcp, void* user)
{
    struct Callback* c = (struct Callback*)user;
    if (c->log_handle == LUA_NOREF) {
        return;
    }
    lua_rawgeti(c->L, LUA_REGISTRYINDEX, c->log_handle);
    lua_pushstring(c->L, log);
    lua_pcall(c->L, 1, 0, 0);
}

static void kcp_output_callback(const char* buf, int len, uint8_t channelID, void* arg)
{
    struct Callback* c = (struct Callback*)arg;
    lua_rawgeti(c->L, LUA_REGISTRYINDEX, c->handle);
    lua_pushlstring(c->L, buf, len);
    lua_pushinteger(c->L, channelID);
    lua_pcall(c->L, 2, 0, 0);
    return;
}

static void free_callback(lua_State* L, struct Callback* cb)
{
    if (cb) {
        if (cb->handle != LUA_NOREF) {
            luaL_unref(L, LUA_REGISTRYINDEX, cb->handle);
        }
        if (cb->log_handle != LUA_NOREF) {
            luaL_unref(L, LUA_REGISTRYINDEX, cb->log_handle);
        }
        free(cb);
    }
}

static int kcp_gc(lua_State* L)
{
    ikcpcb* kcp = check_kcp(L, 1);
    if (kcp) {
        free_callback(L, kcp->user);
        ikcp_release(kcp);
    }
    return 0;
}

static int kcp_create(lua_State* L)
{
    struct Callback* c = malloc(sizeof(struct Callback));
    c->log_handle = LUA_NOREF;
    int n = lua_gettop(L);
    assert(n <= 3);
    if (n == 3) {
        if (lua_isnil(L, 3)) {
            lua_pop(L, 1);
        } else {
            c->log_handle = luaL_ref(L, LUA_REGISTRYINDEX);
        }
    }

    c->handle = luaL_ref(L, LUA_REGISTRYINDEX);
    uint32_t conv = luaL_checkinteger(L, 1);

    lua_rawgeti(L, LUA_REGISTRYINDEX, LUA_RIDX_MAINTHREAD);
    c->L = lua_tothread(L, -1);
    lua_pop(L, 1);

    ikcpcb* kcp = ikcp_create(conv, (void*)c);
    if (kcp) {
        kcp->rx_minrto = 30;
        kcp->output = kcp_output_callback;
        kcp->writelog = kcp_writelog_callback;

        *(ikcpcb**)lua_newuserdata(L, sizeof(void*)) = kcp;
        luaL_getmetatable(L, "kcp2_meta");
        lua_setmetatable(L, -2);
        return 1;
    }

    free_callback(L, c);
    lua_pushnil(L);
    lua_pushstring(L, "error: fail to create kcp");
    return 2;
}

static int kcp_recv(lua_State* L)
{
    ikcpcb* kcp = check_kcp(L, 1);
    if (kcp == NULL) {
        lua_pushinteger(L, -4);
        lua_pushstring(L, "error: kcp not args");
        return 2;
    }

    lua_getfield(L, LUA_REGISTRYINDEX, "kcp_lua_recv_buffer");
    char* buf = check_buf(L, -1);
    lua_pop(L, 1);

    int hr = ikcp_recv(kcp, buf, RECV_BUFFER_LEN);
    lua_pushinteger(L, hr);
    if (hr > 0) {
        lua_pushlstring(L, buf, hr);
        return 2;
    }
    return 1;
}

static int kcp_send(lua_State* L)
{
    ikcpcb* kcp = check_kcp(L, 1);
    if (kcp == NULL) {
        lua_pushinteger(L, -4);
        lua_pushstring(L, "error: kcp not args");
        return 2;
    }

    size_t size;
    const char* data = luaL_checklstring(L, 2, &size);
    lua_pushinteger(L, ikcp_send(kcp, data, size));
    return 1;
}

static int kcp_update(lua_State* L)
{
    ikcpcb* kcp = check_kcp(L, 1);
    if (kcp) {
        ikcp_update(kcp, luaL_checkinteger(L, 2));
        lua_pushinteger(L, kcp->nsnd_que < 10000 ? 0 : -1);
        return 1;
    }

    lua_pushinteger(L, -4);
    lua_pushstring(L, "error: kcp not args");
    return 2;
}

static int kcp_flush(lua_State* L)
{
    ikcpcb* kcp = check_kcp(L, 1);
    if (kcp) {
        ikcp_do_update(kcp, luaL_checkinteger(L, 2));
        return 0;
    }

    lua_pushinteger(L, -4);
    lua_pushstring(L, "error: kcp not args");
    return 2;
}

static int kcp_input(lua_State* L)
{
    ikcpcb* kcp = check_kcp(L, 1);
    if (kcp) {
        uint32_t ts = luaL_checkinteger(L, 2);
        size_t size;
        const char* data = luaL_checklstring(L, 3, &size);
        lua_pushinteger(L, ikcp_input(kcp, ts, data, size));
        return 1;
    }

    lua_pushinteger(L, -4);
    lua_pushstring(L, "error: kcp not args");
    return 2;
}

static int kcp_wndsize(lua_State* L)
{
    ikcpcb* kcp = check_kcp(L, 1);
    if (kcp) {
        int sndwnd = luaL_checkinteger(L, 2);
        int rcvwnd = luaL_checkinteger(L, 3);
        ikcp_wndsize(kcp, sndwnd, rcvwnd);
        return 0;
    }

    lua_pushinteger(L, -4);
    lua_pushstring(L, "error: kcp not args");
    return 2;
}

static int kcp_nodelay(lua_State* L)
{
    ikcpcb* kcp = check_kcp(L, 1);
    if (kcp) {
        int nodelay = luaL_checkinteger(L, 2);
        int interval = luaL_checkinteger(L, 3);
        int resend = luaL_checkinteger(L, 4);
        int nc = luaL_checkinteger(L, 5);
        ikcp_nodelay(kcp, nodelay, interval, resend, nc);
        return 0;
    }

    lua_pushinteger(L, -4);
    lua_pushstring(L, "error: kcp not args");
    return 2;
}

static int kcp_setmtu(lua_State* L)
{
    ikcpcb* kcp = check_kcp(L, 1);
    if (kcp) {
        lua_pushinteger(L, ikcp_setmtu(kcp, luaL_checkinteger(L, 2)));
        return 1;
    }

    lua_pushinteger(L, -4);
    lua_pushstring(L, "error: kcp not args");
    return 2;
}

static int kcp_waitsnd(lua_State* L)
{
    ikcpcb* kcp = check_kcp(L, 1);
    if (kcp) {
        lua_pushinteger(L, ikcp_waitsnd(kcp));
        return 1;
    }

    lua_pushinteger(L, -4);
    lua_pushstring(L, "error: kcp not args");
    return 2;
}

static int kcp_logmask(lua_State* L)
{
    ikcpcb* kcp = check_kcp(L, 1);
    if (kcp) {
        kcp->logmask = luaL_checkinteger(L, 2);
        return 0;
    }

    lua_pushinteger(L, -4);
    lua_pushstring(L, "error: kcp not args");
    return 2;
}

static int kcp_sendcount(lua_State* L)
{
    ikcpcb* kcp = check_kcp(L, 1);
    if (kcp) {
        // TODO andy:
        // lua_pushinteger(L,ikcp_sendcount(kcp));
        lua_pushinteger(L, 0);
        return 1;
    }

    lua_pushinteger(L, -4);
    lua_pushstring(L, "error: kcp not args");
    return 2;
}

static int kcp_timeoutcount(lua_State* L)
{
    ikcpcb* kcp = check_kcp(L, 1);
    if (kcp) {
        // TODO andy:
        // lua_pushinteger(L, ikcp_timeoutcount(kcp));
        lua_pushinteger(L, 0);
        return 1;
    }

    lua_pushinteger(L, -4);
    lua_pushstring(L, "error: kcp not args");
    return 2;
}

static int kcp_fastsndcount(lua_State* L)
{
    ikcpcb* kcp = check_kcp(L, 1);
    if (kcp) {
        // TODO andy:
        // lua_pushinteger(L, ikcp_fastsndcount(kcp));
        lua_pushinteger(L, 0);
        return 1;
    }

    lua_pushinteger(L, -4);
    lua_pushstring(L, "error: kcp not args");
    return 2;
}

static int kcp_minrto(lua_State* L)
{
    ikcpcb* kcp = check_kcp(L, 1);
    if (kcp) {
        kcp->rx_minrto = luaL_checkinteger(L, 2);
        return 0;
    }

    lua_pushinteger(L, -4);
    lua_pushstring(L, "error: kcp not args");
    return 2;
}

static int kcp_set_full_dual_channel(lua_State* L)
{
    ikcpcb* kcp = check_kcp(L, 1);
    if (kcp) {
        kcp->FullDualChannel = luaL_checkinteger(L, 2);
    }
    return 0;
}

static int kcp_enable_channel(lua_State* L)
{
    ikcpcb* kcp = check_kcp(L, 1);
    if (kcp) {
        ikcp_enable_channel(kcp, luaL_checkinteger(L, 2));
    }
    return 0;
}

static int kcp_disable_channel(lua_State* L)
{
    ikcpcb* kcp = check_kcp(L, 1);
    if (kcp) {
        ikcp_disable_channel(kcp, luaL_checkinteger(L, 2));
    }
    return 0;
}

static const struct luaL_Reg kcp_methods[] = {
    {"recv", kcp_recv},
    {"send", kcp_send},
    {"update", kcp_update},
    {"flush", kcp_flush},
    {"input", kcp_input},
    {"wndsize", kcp_wndsize},
    {"nodelay", kcp_nodelay},
    {"setmtu", kcp_setmtu},
    {"waitsnd", kcp_waitsnd},
    {"logmask", kcp_logmask},
    {"sndcnt", kcp_sendcount},
    {"timeoutcnt", kcp_timeoutcount},
    {"fastsndcnt", kcp_fastsndcount},
    {"minrto", kcp_minrto},
    {"set_full_dual_channel", kcp_set_full_dual_channel},
    {"enable_channel", kcp_enable_channel},
    {"disable_channel", kcp_disable_channel},
    {NULL, NULL},
};

static const struct luaL_Reg l_methods[] = {
    {"create", kcp_create},
    {NULL, NULL},
};

#ifdef _MSC_VER
__declspec(dllexport) int luaopen_kcp2(lua_State *L)
#else
int luaopen_kcp2(lua_State* L)
#endif
{
    luaL_checkversion(L);

    luaL_newmetatable(L, "kcp2_meta");
    lua_newtable(L);
    luaL_setfuncs(L, kcp_methods, 0);
    lua_setfield(L, -2, "__index");
    lua_pushcfunction(L, kcp_gc);
    lua_setfield(L, -2, "__gc");

    luaL_newmetatable(L, "recv_buffer");
    char* global_recv_buffer = lua_newuserdata(L, RECV_BUFFER_LEN);
    luaL_getmetatable(L, "recv_buffer");
    lua_setmetatable(L, -2);
    lua_setfield(L, LUA_REGISTRYINDEX, "kcp_lua_recv_buffer");

    luaL_newlib(L, l_methods);

    return 1;
}
