FROM alpine:3.20

# Install telegraf + tools used by the Lua scripts
RUN apk add --no-cache \
      telegraf \
      curl \
      arp-scan \
      luajit \
      iputils-ping

# Copy Telegraf config
COPY telegraf.conf /etc/telegraf/telegraf.conf

# Copy LuaJIT scripts
COPY net_active_devices.lua /usr/local/bin/net_active_devices.lua
COPY internet_speed.lua     /usr/local/bin/internet_speed.lua

RUN chmod +x /usr/local/bin/net_active_devices.lua \
             /usr/local/bin/internet_speed.lua

CMD ["/usr/bin/telegraf", "--config", "/etc/telegraf/telegraf.conf"]
