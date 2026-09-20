FROM node:20-alpine
WORKDIR /app
COPY package.json server.js ./
ENV NODE_OPTIONS=--openssl-legacy-provider
ENV PORT=8081
EXPOSE 8081
CMD ["node", "server.js"]
