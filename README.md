node-security-middleware
========================

## About

node-security-middleware is a security middleware for [Connect](http://senchalabs.github.com/connect/)/[Express](http://expressjs.com/)

It supplies both BASIC and FORM authentication, as well as authorization based on an Access Control List.
The latter is a set of rules that can be defined per url and rely on privileges and roles granted to the authenticated user.
The authentication as well as the authorization mechanisms rely on a store which will be used to retrieve the user credentials as well as its roles and privileges.

Installation
====================

    $ npm install security-middleware

Using It
====================

### Configure security-middleware within express

    var security = require('security-middleware')
    , inMemoryStore = require('security-middleware/lib/security.js').inMemoryStore;

    var app = express();

    app.configure(function(){
    ...
      app.use(security({ 
        debug : false, // for debug purpose
        realmName : 'Express-security', // realm name
        store : inMemoryStore, // store which will be used to retrieve user information - inMemoryStore by default if none specified
        rememberMe : true, // whether a cookie will be set after authentication or not - false by default
        secure : true, // whether to use secured cookies or not - false by default
        credentialsMatcher: 'sha256', // a credentialsMatcher must be provided to check if the provided token credentials match the stored account credentials using the encrypted algoithm specified
        loginUrl : '/login', // url used by the application to sign in - `/login` by default
        usernameParam : 'username', // name of the username parameter which will be used during form authentication
        passwordParam : 'password', // name of the password parameter which will be used during form authentication
        logoutUrl : '/logout', // url used by the application to sign out - `/logout` by default
        acl : [ // array of Access Controls to apply per url
               {
                   url : '/admin', // web resource (s) on which this access control will be applied - `/*` if none specified
                   methods : 'GET, POST', // HTTP method (s) for which this access control will be applied (GET, POST, PUT, DELETE or * for ALL) - `*` by default
                   authentication : 'BASIC', // authentication type - FORM or BASIC
                   rules : '(([role=user] && [permission=admin]) || [role=admin])' // access control rules to check
               },
               {
                   url : '/products/list',
                   methods : 'GET',
                   authentication : 'FORM',
                   // a rule can be based on query parameter (s) which will be valued at runtime (eg {idCompany})
                   rules : '(([role=user] && [permission=products:company_{idCompany}:list]) || [role=admin])'
               }
        ]
      }));
      ...
    });

### Use inMemoryStore

### Define a custom Store

### Define an Access Control rule

### Subject api
