# Encrypted chat messages
##### How to run using docker ?
Pull the docker image
<br>`docker pull alanensina/crypto-messages`

Run the container
<br>`docker container run -it alanensina/crypto-messages`

##### How to run via terminal?
###### Requirements:
- Java 8+
- Maven 3.8+

###### Steps:
- Access the project folder through the terminal
- Install dependencies: 
`mvn clean install`
- Access the target folder: 
`cd /target`
- Run the app: 
`java -jar crypto-0.0.1-SNAPSHOT.jar`
