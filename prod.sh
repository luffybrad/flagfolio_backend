# script to run docker backend


#stop all running containers
docker stop my-mysql flagfolio_backend
#remove any existing containers and respective volumes(-v)
docker rm -v my-mysql 
docker rm flagfolio_backend
docker rm ngrok_tunnel

#build new backend image and push
#this allows all changes to be reflected in the image tagged latest
docker build --platform linux/amd64,linux/arm64 -t braddev2/flagfolio_backend:latest .
docker push braddev2/flagfolio_backend:latest 



# mysql script
docker pull mysql:latest
docker run --name my-mysql -e MYSQL_ROOT_PASSWORD=3353 -e MYSQL_DATABASE=flagfolio_data -p 3306:3306 -v mysql-data:/var/lib/mysql -d mysql:latest


#backend script
docker pull braddev2/flagfolio_backend:latest
#run backend container and allow for automatic container update when backend files are modified without rebuilding entire image
# --mount option allows container to instantly reflect any changes made to files in the local backend directory
# Check the docker file CMD command (i.e. Nodemon is used to to allow monitoring change in index.js file )
docker run --name flagfolio_backend -p 5000:5000 --link my-mysql --mount type=bind,source="$(pwd)",target=/usr/src/app -d braddev2/flagfolio_backend:latest



#ngrok script
#this allows the localhost ip and port i.e 'http://localhost:5000' to be accessed through the specified custom domain (ngrock static domain)
docker pull ngrok/ngrok:latest
docker run --name ngrok_tunnel --link flagfolio_backend -it -e NGROK_AUTHTOKEN=2pnh6b8E5xUSBxje6bcwMpFNoAf_4XWK1oFSR9ucqkPcoMzV7 ngrok/ngrok:latest http --url=wren-wealthy-minnow.ngrok-free.app flagfolio_backend:5000