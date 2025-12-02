FROM alpine:3.20

# Install Grafana
RUN apk add --no-cache grafana

# Create data & dashboards directory
RUN mkdir -p /var/lib/grafana/dashboards

# Copy our grafana.ini
COPY grafana.ini /etc/grafana/grafana.ini

# Copy provisioning configs (datasources + dashboards)
COPY provisioning /etc/grafana/provisioning

EXPOSE 3000

CMD ["/usr/sbin/grafana-server", \
     "--homepath=/usr/share/grafana", \
     "--config=/etc/grafana/grafana.ini"]
