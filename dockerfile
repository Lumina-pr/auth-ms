FROM node:24.10.0-alpine

WORKDIR /usr/src/app

COPY  package*.json ./

RUN npm install


COPY . .

EXPOSE 3000