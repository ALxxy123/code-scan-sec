# Use a lightweight base image
FROM alpine:latest

# Install necessary dependencies
RUN apk --no-cache add bash git jq

# Set up a working directory
WORKDIR /app

# Copy the application files into the container
COPY . .

# Make the scripts executable
RUN chmod +x /app/bin/*.sh

# Define the entry point for the container
ENTRYPOINT ["/app/bin/scan.sh"]

# The default command will be to scan the current directory (can be overridden)
CMD ["."]
