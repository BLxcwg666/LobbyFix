# LobbyFix

A [Metamod:Source](https://www.metamodsource.net/) plugin that makes **CS:GO legacy (1.38.8.1) dedicated servers joinable again** by direct connect, over LAN and the public internet.

## Why do this

在 CS2 之后，老的 CSGO GC 应该是死透了，所以自己开的服务器大概会遇到进度条一滑到底然后回到大厅啥报错也没有的问题  
然后做了这个，解决这个问题  

Linux 没测，不知道能不能用

## About auth issue
如果你在本地或者说局域网环境下或者说 N 层 NAT 之后的环境下开服务器并且使用了类似 frp 的内网穿透工具  
并且你的客户端在加入时报 "Client dropped by server" 或者 "No user logon"  
可以尝试使用[该分支](https://github.com/BLxcwg666/LobbyFix/tree/keepAuth)的构建

## License

Public Domain
