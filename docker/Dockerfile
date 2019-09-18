FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH alsvc_metapeek.metapeek.MetaPeek

# Switch to assemblyline user
USER assemblyline

# Copy MetaPeek service code
WORKDIR /opt/al/al_services/alsvc_metapeek
COPY . .