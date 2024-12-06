# Use the official Node.js image as the base image
FROM node:latest

# Set the working directory inside the container
WORKDIR /usr/src/app

# Copy package.json and package-lock.json to the container
COPY package*.json ./

# Install dependencies
RUN npm install

# Install nodemon globally in docker container to allow use in cmd
RUN npm install -g nodemon

# Copy the rest of the application code to the container
COPY . .

# Expose the port that the application will run on
EXPOSE 5000

# Command to start the Node.js application (nodemon to monitor any changes in code)
CMD ["nodemon", "index.js"]


