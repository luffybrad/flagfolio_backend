# script to run docker backend


#stop all running containers
docker stop my-mysql flagfolio_backend
#remove any existing containers and respective volumes(-v)
docker rm -v my-mysql 
docker rm flagfolio_backend


#build new backend image and push
#this allows all changes to be reflected in the image tagged latest
docker build --platform linux/amd64,linux/arm64 -t braddev2/flagfolio_backend:latest .
docker push braddev2/flagfolio_backend:latest 



# mysql script
docker pull mysql:latest
docker run --name my-mysql -e MYSQL_ROOT_PASSWORD=3353 -e MYSQL_DATABASE=flagfolio_data -p 3306:3306 -v mysql-data:/var/lib/mysql -d mysql:latest

#backend script
docker pull braddev2/flagfolio_backend:latest
docker run --name flagfolio_backend -p 5000:5000 --link my-mysql -d braddev2/flagfolio_backend:latest
