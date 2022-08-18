# NordAlign

### install
without docker, ubuntu 20
install conda python 3.8
conda install -c conda-forge montreal-forced-aligner

### download corpus
mfa model download acoustic english
mfa model download dictionary english

### install mongodb

https://www.digitalocean.com/community/tutorials/how-to-install-mongodb-on-ubuntu-20-04
https://linuxhint.com/install_mongodb_ubuntu_20_04/

create database inside `mongo` shell, `use mydb`

## How to use the template

Simply insert your MongoDB database URI and database name in the ```configuration.ini``` file. You can also add SMTP server login details to support sending registration emails and message notifications to users.

Run the app using the terminal command: ```python run.py```

## Live example

