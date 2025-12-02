FROM alpine:3.20

# Install InfluxDB (v1.x on Alpine)
RUN apk add --no-cache influxdb

# Data directory will be mounted from host
RUN mkdir -p /var/lib/influxdb

EXPOSE 8086

# Default config is fine for local use; change via mounted config if needed
CMD ["/usr/bin/influxd"]
