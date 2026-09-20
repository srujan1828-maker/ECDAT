FROM node:20-alpine
WORKDIR /app
COPY package.json server.js ./
ENV NODE_OPTIONS=--openssl-legacy-provider
ENV PORT=8082
EXPOSE 8082
CMD ["node", "server.js"]
