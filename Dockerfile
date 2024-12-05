# Use the official Node.js image as the base image
FROM node:lts-slim

# Set the working directory inside the container
WORKDIR /usr/src/app

# Copy package.json and package-lock.json to the container
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy the rest of the application code to the container
COPY . .

# Expose the port that the application will run on
EXPOSE 5000

# Command to start the Node.js application
CMD ["node", "index.js"]