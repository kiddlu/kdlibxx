#include <lua5.1/lua.h>
#include <lua5.1/lualib.h>
#include <lua5.1/lauxlib.h>

int main(int argc, char *argv[])
{
    lua_State *L = luaL_newstate(); //打开Lua，创建新的环境
    luaL_openlibs(L); //打开所有的标准库

    const char *buf = "print('Hello World')"; //Lua代码
    luaL_dostring(L, buf); //相当于Lua代码中的dostring

    lua_close(L); //关闭Lua状态
    return 0;
}
