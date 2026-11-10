# Docker image for the xTremio addon.
#
# Build it:  docker build -t xtremio .
# Run it:    docker run -d --name xtremio -p 3000:3000 --env-file .env xtremio
#
# More in the "Option 2: Docker" section of README.md.

# Start from the official Node.js image ("alpine" = small Linux).
FROM node:24-alpine

# Show this GitHub repo as the image's source on ghcr.io.
LABEL org.opencontainers.image.source=https://github.com/izemhsn/xTremio-stremio-addon

# The folder inside the container where the app lives.
WORKDIR /app

# Install dependencies first. Docker reuses this step until
# package.json or package-lock.json changes, so rebuilds are fast.
# --omit=dev skips tools that are only needed for tests, and the cache
# clean drops npm's download cache, which the image never uses again.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

# Copy the app code.
COPY index.js ./
COPY src ./src

# In production mode the addon will not start without CONFIG_SECRET.
ENV NODE_ENV=production

# Don't run as root (the "node" user comes with the image).
USER node

# The addon listens on port 3000.
EXPOSE 3000

# Every 30 seconds Docker opens /health. If it fails 3 times in a row,
# `docker ps` shows the container as "unhealthy".
HEALTHCHECK CMD wget -q -O /dev/null http://127.0.0.1:3000/health || exit 1

# Start the addon.
CMD ["node", "index.js"]
