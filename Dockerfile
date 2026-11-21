FROM node:22-alpine AS builder
WORKDIR /app

COPY package.json bun.lock* package-lock.json* ./
RUN npm ci

COPY . .
RUN npm run lint && npm test && npm run build

FROM node:22-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=3000

COPY package.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist

USER node
EXPOSE 3000
CMD ["node", "dist/server.cjs"]
