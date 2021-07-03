# Passify-Password-Manager

Passify is an online password manager designed keeping in mind the growing need of remembering lots of passwords. Internet applications have seen an exponential growth over the years and as new services come into existence, we tend to register ourselves using username and password. With the projected growth, it will soon be impossible to remember the passwords of each and every service that one uses and ***Passify*** comes to the rescue.

![image](https://user-images.githubusercontent.com/46895613/124361950-b872f200-dc4f-11eb-9217-8a407520798b.png)


## 💻 Tech Stack

* HTML
* CSS
* JavaScript
* Flask backend (Python)
* MySQL DB

## ✨ Salient Features

* User Login / Sign-Up
* Google OAuth2.0 based authentication
* State of the art cryptography algorithms - ***AES*** and ***DES***
* Integration of AES with 128-bit key, 192-bit key, or 256-bit key
* Integration of DES algorithm having of types CBC and OFB 
* Option to choose algorithm for encryption & decryption
* Fast encryption and Decryption
* Dual encryption - one by user and one by admin
* Storage in a secure MySQL DB which can be local or hosted
* Dual decryption to access stored password
* One global password to access multiple passwords across various websites
* Direct login to desired website
* Encrypted communication between client and backend server
* Dependency of encrypted text on encryption key as well as Initialization Vector (IV)
* Global password stored after hashing and salting to prevent plaintext leaks
* MySQL injection sanitization using Prepared Statements
* Web based UI and access across multiple platforms through browser
* Lightweight and simplistic - easy to deploy

## ⚡ Installation and Usage

The application runs on Flask backend so make sure python and pip are installed in your system.

* Setup a virtual environment
  ```
  pip install virtualenv
  virtualenv venv
  venv\scripts\activate
  ```
* Install all the dependencies - Flask, pycryptodome, Flask MySQL driver using pip installer
 
* Run the application
  ```
  python main.py
  ```

## 📷 Screenshots from the implementation

The below images illustrate the application usage to store and retrieve passwords

![image](https://user-images.githubusercontent.com/46895613/124362225-4d2a1f80-dc51-11eb-9d92-0cfc93ba810e.png)

![image](https://user-images.githubusercontent.com/46895613/124362232-561af100-dc51-11eb-9c5c-5e91e230e935.png)

![image](https://user-images.githubusercontent.com/46895613/124362235-5fa45900-dc51-11eb-9ad7-24461ecbeda4.png)

![image](https://user-images.githubusercontent.com/46895613/124362241-6a5eee00-dc51-11eb-83d9-c3c660d590c8.png)

![image](https://user-images.githubusercontent.com/46895613/124362243-6e8b0b80-dc51-11eb-9bca-dd1556c4e8c4.png)

<br>

The below images illustrate how data is stored in the DB after two rounds of encryption

![image](https://user-images.githubusercontent.com/46895613/124362249-75b21980-dc51-11eb-9066-bbb88a6b69d9.png)

![image](https://user-images.githubusercontent.com/46895613/124362257-7d71be00-dc51-11eb-8eac-86545d1b1bb7.png)


## 🏢 Future Work

*  Extend the application for Android and iOS devices
*  Add more security to the application
*  Safeguard against other common attacks like CSRF, XSS, etc.
*  Containerize the application for easy deployment

Contributions are welcome. If you want to contribute in any of the above ***Future Works*** , we can discuss on the feature and how to go about it and later make a PR to the codebase. For other contributions, feel free to raise a PR.




