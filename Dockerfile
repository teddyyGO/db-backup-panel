# db-backuper — Node + MySQL/MariaDB client (for mysqldump / mariadb-dump)
FROM node:20-bookworm-slim

# default-mysql-client on Debian installs the MariaDB client, which provides
# both `mariadb-dump` and a `mysqldump` compatibility symlink. It can dump
# MariaDB and MySQL servers alike.
RUN apt-get update \
 && apt-get install -y --no-install-recommends default-mysql-client \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package*.json ./
RUN npm install --omit=dev

COPY . .

ENV NODE_ENV=production
EXPOSE 3000

CMD ["node", "server.js"]
