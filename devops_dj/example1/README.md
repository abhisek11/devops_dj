[![Build Status](https://travis-ci.com/SecureYourInbox/brandsecure-backend.svg?token=JrXTxWLySxmRPPFkDhGA&branch=master)](https://travis-ci.com/SecureYourInbox/brandsecure-backend) [![codecov](https://codecov.io/gh/SecureYourInbox/brandsecure-backend/branch/master/graph/badge.svg?token=DNZZRI9A4S)](https://codecov.io/gh/SecureYourInbox/brandsecure-backend) [![Python 3.7](https://img.shields.io/badge/python-3.7-blue.svg)](https://www.python.org/downloads/release/python-370/) 

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

