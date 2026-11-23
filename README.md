# LobbyFix

A [Metamod:Source](https://www.metamodsource.net/) plugin that makes **CS:GO legacy (1.38.8.1) dedicated servers joinable again** by direct connect, over LAN and the public internet.

## Why do this

在 CS2 之后，老的 CSGO GC 应该是死透了，所以自己开的服务器大概会遇到进度条一滑到底然后回到大厅啥报错也没有的问题  
然后做了这个，解决这个问题  

Linux 没测，不知道能不能用

## About auth issue
如果你在本地 / 局域网 / N 层 NAT 之后的环境下开服务器并且使用了类似 frp 的内网穿透工具  
并且你的客户端在加入时报 "Client dropped by server" 或者 "No user logon"  
尝试在安装插件的同时在 srcds 启动参数里加上 `-lobbyfix_keepauth`  
（**Unsafe!** 请确保在受信任的网络环境中使用这个）  

## License

AGPL v3
