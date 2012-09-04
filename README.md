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

```javascript
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
        credentialsMatcher: 'sha256', // a credentialsMatcher must be provided to check if the provided token credentials match the stored account credentials using the encryption algorithm specified
        loginUrl : '/login', // url used by the application to sign in - `/login` by default
        usernameParam : 'username', // name of the username parameter which will be used during form authentication - `username` by default
        passwordParam : 'password', // name of the password parameter which will be used during form authentication - `password` by default
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

```

### Use FORM authentication within express

Whenever an access control applies to an unauthenticated or unauthorized user, the client is automatically redirected to the `loginUrl` defined for the security middleware.

The login form should include `usernameParam` and `passwordParam` as defined for the security middleware.

```javascript
app.get('/login', function(req, res){
  res.render('login', { username: req.param('username') });
});
```

The login form may also include a `redirect` input so as to automatically redirect the client to the uri initially requested after authentication completion.

```javascript
app.get('/login', function(req, res){
  res.render('login', { username: req.param('username'), redirect : req.param('redirect') });
});
```

```html
<!DOCTYPE html>
<html>
  <head>
    <title>Login</title>
  </head>
  <body>
    <h1>Login</h1>
    <form method="post">
      <input type="text" name="username" placeholder="Type your login" autofocus required<% if (username) { %> value="<%= username %>"<% } %>>
      <input type="password" name="password" placeholder="Type your password" required>
      <input type="hidden" name="redirect"<% if (redirect) { %> value="<%= redirect %>"<% } %>>
      <input type="submit">
    </form>
  </body>
</html>
```

### Use inMemoryStore

The inMemoryStore should not be used in a production environment. It may nevertheless be useful during the development phase.

It allows to save in memory both users and roles as in the example below.

```javascript
var inMemoryStore = require('security-middleware/lib/security.js').inMemoryStore
, credentialsMatcher = require('security-middleware/lib/security.js').sha256CredentialsMatcher 
, encryptedPassword = credentialsMatcher.encrypt('changeit');

inMemoryStore.storeRole({
    name : 'user', // must be unique
    privileges : [] // may be empty or null
});

inMemoryStore.storeRole({
    name : 'admin',
    privileges : [ 'admin:*' ]
});

inMemoryStore.storeAccount({
    username : 'user', // must be unique
    password : encryptedPassword, // must be encrypted using the same encryption algorithm which will be used by the security middleware
    roles : ['user'], // set of roles granted to the user
    privileges : [ 'products:company_1:list', 'products:company_1:show:*' ] // set of privileges granted to the user
});

inMemoryStore.storeAccount({
    username : 'admin',
    password : encryptedPassword,
    roles : [ 'user', 'admin' ],
    privileges : []
});

```

### Define a custom Store

A custom Store must conform to the interface below :

```javascript
/**
 * Returns the user mapped to this username or null
 * 
 * If exists, the returned object should include the user's password
 * 
 * @param username
 * @returns the user mapped to this username or null
 */
Store.prototype.lookup = function(username) {
    ...
};

/**
 * Returns the roles granted to the user mapped to this username as an array of string
 * 
 * @param username
 * @returns the roles granted to the user mapped to this username as an array of string
 */
Store.prototype.loadUserRoles = function(username) {
    ...
};

/**
 * Returns the privileges granted to the user mapped to this username as an array of string
 * 
 * @param username
 * @returns the privileges granted to the user mapped to this username as an array of string
 */
Store.prototype.loadUserPrivileges = function(username) {
    ...
};

/**
 * Returns the privileges granted to the role mapped to this role name as an array of string
 * 
 * @param roleName
 * @returns the privileges granted to the role mapped to this role name as an array of string
 */
Store.prototype.loadRolePrivileges = function(roleName) {
    ...
};

```

### Define an Access Control

#### Define an Access Control mapping

An Access Control mapping is looked up for every client request based on the url requested as well as the http method.

For instance, for the following request,

    GET /products/1/list

a matching will be looked up as follow :
 
AccessControl contains `GET` or `*` method and has been defined for one of the following url :

    /products/1/list
    /products/1/list/* 
    /products/1/*
    /products/*
    /*

```javascript
{
    url : '/products/list',
    methods : 'GET',
    authentication : 'FORM',
    rules : '(([role=user] && [permission=products:company_{idCompany}:list]) || [role=admin])'
}
```

will apply to :

    GET /products/list


```javascript
{
    url : '/products',
    methods : 'GET',
    authentication : 'FORM',
    rules : '(([role=user] && [permission=products:company_{idCompany}:show:product_{idProduct}]) || [role=admin])'
}
```

will apply to :

    GET /products

```javascript
{
    url : '/products',
    methods : 'PUT',
    authentication : 'FORM',
    rules : '(([role=user] && [permission=products:company_{idCompany}:create]) || [role=admin])'
}
```

will apply to :

    PUT /products

```javascript
{
    url : '/products',
    methods : 'POST',
    authentication : 'FORM',
    rules : '(([role=user] && [permission=products:company_{idCompany}:update]) || [role=admin])'
}
```

will apply to :

    POST /products

```javascript
{
    url : '/products',
    methods : 'DELETE',
    authentication : 'FORM',
    rules : '(([role=user] && [permission=products:company_{idCompany}:delete]) || [role=admin])'
}
``` 

will apply to :

    DELETE /products

#### Define Access Control rules

Access Control rules are based on a set of role (s) and/or permission (s) which must have been granted to the authenticated user in order to authorize the latter to access the requested web ressource.

A required role is defined as follow :

    [role=roleName]

A required permission is defined as follow :

    [permission=permissionRule]

It is also possible to specify permissions based on request parameters that will be evaluated at runtime.

A request parameter `parmaterName` may be added using the following syntax :

    {parmaterName}

The following permission

    [permission=products:company_{idCompany}:list]

that applies to

    GET /products/list?idCompany=1

will be evaluated at runtime as below :

    products:company_1:list

Finally, Access Control rules may use logical operators.

For instance, for the following request,

	GET /products/list?idCompany=1

The following Access Control rules will apply

    '(([role=user] && [permission=products:company_{idCompany}:list]) || [role=admin])'

for which a matching will be looked up as follow :

The role `user` has been granted to the authenticated user `and` one of the following privilege has been granted to the authenticated user :

    products:company_1:list
    products:company_1:list:*
    products:company_1:*
    products:*
    *

`or` the role `admin` has been granted to the authenticated user

### Subject api

An instance of Subject is added to all incoming requests and can be accessed as in the example below :

```javascript
app.get('/products/list', function(req, res){
    var subject = req.subject;
    ...
});

```

Subject defines the api described below :

```javascript
/**
 * Returns this Subject's uniquely-identifying principal, or null 
 * if this Subject doesn't yet have account data associated with it
 */
Subject.prototype.getPrincipal = function(){
...
}
/**
 * Returns true if this Subject has the specified role, false otherwise.
 */
Subject.prototype.hasRole = function(roleName){
...
}
/**
 * Returns true if this Subject has all of the specified roles, false otherwise.
 */
Subject.prototype.hasAllRoles = function(roles){
...
};
/**
 * Returns true if the Subject is permitted to perform an action or access a 
 * resource summarized by the specified permission string.
 */
Subject.prototype.isPermitted = function(permission) {
...
};
/**
 * Returns true if the Subject implies all of the specified permission strings.
 */
Subject.prototype.isPermittedAll = function(permissions) {
...
};
/**
 * Returns true if this Subject/user has proven their identity during their current session
 * by providing valid credentials matching those known to the system, false otherwise.
 */
Subject.prototype.isAuthenticated = function(){
...
};
/**
 * Performs a login attempt for this Subject/user. If unsuccessful, an error is thrown.
 * If successful, the account data associated with the submitted principals/credentials 
 * will be associated with this Subject and the method will return quietly.
 * 
 * Upon returninq quietly, this Subject instance can be considered authenticated 
 * and getPrincipal() will be non-null and isAuthenticated() will return true.
 */
Subject.prototype.login = function(token){
...
};
/**
 * Logs out this Subject and invalidates and/or removes any associated entities 
 * and authorization data.
 */
Subject.prototype.logout = function(){
...
};

```

A call to Subject.login requires a token which should be initialized using `UsernamePasswordToken` :

```javascript
var UsernamePasswordToken = require('security-middleware/lib/security.js').UsernamePasswordToken;
// user's password should not be encrypted within a token, otherwise the credentials matcher will not work
subject.login(new UsernamePasswordToken(username, password, rememberMe));

```
