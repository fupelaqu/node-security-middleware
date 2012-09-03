node-security-middleware
========================

## About

node-security-middleware is a security middleware for [Connect](http://senchalabs.github.com/connect/)/[Node.js](http://nodejs.org)

It supplies both BASIC and FORM authentication, as well as authorization based on an Access Control List.
The latter is a set of rules that can be defined per url and rely on privileges and roles granted to the authenticated user.
The authentication as well as the authorization mechanisms rely on a store which will be used to retrieve the user credentials as well as his roles and privileges.

Installation
====================

    $ npm install security-middleware
    