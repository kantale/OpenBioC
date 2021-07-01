
## How to install
Run these commands only once!

### Install Anaconda 3

```
wget https://repo.anaconda.com/archive/Anaconda3-5.2.0-Linux-x86_64.sh 

bash Anaconda3-5.2.0-Linux-x86_64.sh 

# REPLACE /home/kanterakis with the directory of your anaconda 3 installation
/home/kanterakis/anaconda3/bin/pip install --upgrade pip
/home/kanterakis/anaconda3/bin/pip install virtualenv 

```

A script to install miniconda is available at [install_miniconda.sh](install_miniconda.sh).

### Create A dedicated python installation from Anaconda:
I assume that you have already cloned this repository: ```https://github.com/kantale/OpenBioC```
Go to the directory: ```OpenBioC``` of this repository.

The file ```manage.py``` should be there. 

Create a dedicated python virtualenv:

```
/home/kanterakis/anaconda3/bin/virtualenv OpenBioC_python 
```


Create a dedicate python environment with conda:

```
conda create --name obc_python 
```

### Start the virtualev

```
source OpenBioC_python/bin/activate
```

If you crated a virtual environment with conda, to activate it run:

```
conda activate obc_python 
```

### Install Django 2.1.5

```
pip install Django==2.1.5
```
* Note: Django 2.1.0 [seems to have an issue with SQLite](https://stackoverflow.com/questions/53637182/django-no-such-table-main-auth-user-old)


### Install other useful packages:

```
pip install simplejson
pip install pybtex
pip install mistune
pip install requests
pip install social-auth-app-django
pip install djangorestframework==3.11.0
pip install bashlex
pip install networklex
conda install ansi2html
```

* Build database

```
python manage.py migrate --run-syncdb
python manage.py makemigrations
python manage.py migrate 
```

### Install packages for discourse graph:
```
pip install flask
```

### Install packages for Common Workflow Language (CWL)
```
pip install cwltool
pip install cwlref-runner
```

* Download static files

```
cd app/static/app
python get_bash_commands.py | bash
```

* Run

Change the port if you want. Ports used:
* 8200 : Development
* 8300 : Testing

```
python manage.py runserver 0.0.0.0:8200
```

## How to Run:
Run these commands whenever you want to run/test your changes. I assume you have followed the instruction of how to install. 
Also you can change the port (8200) to anything you like.


```
python manage.py runserver 0.0.0.0:8200
```

Go to  ```http://0.0.0.0:8200``` and check your awesome changes!


## How to setup from Scratch
Ignore these..

```
python manage.py startapp app
```

## Open remotely files with Sublime 3
Follow directions from: https://stackoverflow.com/questions/37458814/how-to-open-remote-files-in-sublime-text-3

If the port is different than the default (52698):

```
export RMATE_HOST=localhost
export RMATE_PORT=52699
```



