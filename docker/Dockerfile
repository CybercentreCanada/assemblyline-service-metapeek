FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH metapeek.MetaPeek

# Switch to assemblyline user
USER assemblyline

# Copy MetaPeek service code
WORKDIR /opt/al_service
COPY . .