FROM node:18-alpine
WORKDIR /app
COPY package*.json .
RUN npm install
RUN mkdir -p /app/uploads/citizenship_images
COPY . .
RUN chmod +x wait-for-it.sh
EXPOSE 3000
CMD ["./wait-for-it.sh", "db:5432", "--", "node", "server.js"]
