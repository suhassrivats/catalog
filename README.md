# Restaurant App
Udacity - item catalog app using Flask.

## Description
This is a data-driven Restaurant Web Application where we can perform all CRUD operations.

## Requirements
Vagrant
VirtualBox
Python ~2.7
Set Up

Install all project dependencies
`pip install -r requirements.txt`

For an initial set up please follow these 2 steps:

Download or clone the [fullstack-nanodegree-vm repository](https://github.com/udacity/fullstack-nanodegree-vm).

Find the catalog folder and replace it with the content of this current repository, by either downloading it or cloning it - Github Link.

## Usage
Launch the Vagrant VM from inside the vagrant folder with:

`vagrant up`

`vagrant ssh`

Then move inside the catalog folder:

`cd /vagrant/catalog`



Then lift the application:

`python project.py`

After the last command you are able to browse the application at this URL:

`http://localhost:5000/restaurants`
