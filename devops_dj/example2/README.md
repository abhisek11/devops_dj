[![Build Status](https://travis-ci.com/SecureYourInbox/brandsecure-backend.svg?token=JrXTxWLySxmRPPFkDhGA&branch=master)](https://travis-ci.com/SecureYourInbox/brandsecure-backend)  [![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=SecureYourInbox_brandsecure-backend&metric=ncloc&token=a90e8b04f5263ca6681a8a1de162d791399c30b6)](https://sonarcloud.io/dashboard?id=SecureYourInbox_brandsecure-backend) [![Bugs](https://sonarcloud.io/api/project_badges/measure?project=SecureYourInbox_brandsecure-backend&metric=bugs&token=a90e8b04f5263ca6681a8a1de162d791399c30b6)](https://sonarcloud.io/dashboard?id=SecureYourInbox_brandsecure-backend) [![Coverage](https://sonarcloud.io/api/project_badges/measure?project=SecureYourInbox_brandsecure-backend&metric=coverage&token=a90e8b04f5263ca6681a8a1de162d791399c30b6)](https://sonarcloud.io/dashboard?id=SecureYourInbox_brandsecure-backend)  [![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=SecureYourInbox_brandsecure-backend&metric=alert_status&token=a90e8b04f5263ca6681a8a1de162d791399c30b6)](https://sonarcloud.io/dashboard?id=SecureYourInbox_brandsecure-backend)  [![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=SecureYourInbox_brandsecure-backend&metric=security_rating&token=a90e8b04f5263ca6681a8a1de162d791399c30b6)](https://sonarcloud.io/dashboard?id=SecureYourInbox_brandsecure-backend)  [![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=SecureYourInbox_brandsecure-backend&metric=vulnerabilities&token=a90e8b04f5263ca6681a8a1de162d791399c30b6)](https://sonarcloud.io/dashboard?id=SecureYourInbox_brandsecure-backend)  [![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=SecureYourInbox_brandsecure-backend&metric=code_smells&token=a90e8b04f5263ca6681a8a1de162d791399c30b6)](https://sonarcloud.io/dashboard?id=SecureYourInbox_brandsecure-backend)

[![Run in Postman](https://run.pstmn.io/button.svg)](https://app.getpostman.com/run-collection/db65c4c12fe923ae6539#?env%5Bbrand-secure-env%5D=W3sia2V5IjoidXJsIiwidmFsdWUiOiJodHRwOi8vMTcyLjIzLjAuMTo4MDAwLyIsImVuYWJsZWQiOnRydWV9LHsia2V5IjoidG9rZW4iLCJ2YWx1ZSI6IjQ2ZmRmMjBhY2JlNzkzNDliYmQ2ODBmZjMyZTA5YzA0NzQ4NWIzODAyYmZmNjg4NjY3ZTk2MDVlMjEwM2I3OTciLCJlbmFibGVkIjp0cnVlfV0=)


### Brand-Secure-Backend

To run a local instance of the application follow the instructions below.

Clone the repository using the command 

 ```git clone <clone_link>```
 
Navigate to the application directory and run any of the commands

```docker build .  or  docker-compose build```

Start the application  and run the server 

```docker-compose up```

In a new terminal window run below command to create superuser for Django admin  dashboard

```docker-compose run app sh -c "python manage.py createsuperuser"```

To access application use command 

```docker-compose run app sh -c "python manage.py test && flake8"```

