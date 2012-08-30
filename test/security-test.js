/* 
 * security unit tests.
 * 
 */

var assert = require('assert')
, security = require('../lib/security.js')
, utils = require('../lib/utils.js');

var usernamePasswordToken = new security.UsernamePasswordToken();
assert.ok(utils.isDefined(usernamePasswordToken));
assert.ok(utils.isUndefined(usernamePasswordToken.username));
assert.ok(utils.isUndefined(usernamePasswordToken.password));
assert.ok(utils.isDefined(usernamePasswordToken.getUsername));
assert.ok(utils.isDefined(usernamePasswordToken.getPrincipal));
assert.ok(utils.isDefined(usernamePasswordToken.isRememberMe));

var credentialsMatcher = security.sha256CredentialsMatcher;

var realm = new security.Realm({
    realm : 'Node.js',
    credentialsMatcher : 'sha256'
});
assert.ok(utils.isDefined(realm));

var store = realm.store;
assert.ok(utils.isDefined(store));

store.storeAccount({
    username : 'user', 
    password : credentialsMatcher.encrypt('changeit'),
    roles: ['user'],
    privileges : []
});
store.storeAccount({
    username : 'admin', 
    password : credentialsMatcher.encrypt('changeit'),
    roles: ['user','admin'],
    privileges : []
});
store.storeRole({
    name : 'user', 
    privileges : []
});
store.storeRole({
    name : 'admin', 
    privileges : ['admin:*']
});
console.log(store);

var user = store.lookup('admin');
assert.ok(utils.isDefined(user));

var token = new security.UsernamePasswordToken(
        'admin', 
        'changeit');
var account = realm.authenticate(token);
assert.ok(utils.isDefined(account));
console.log(account);
assert.ok(utils.isEqual(user.username, account.principal));

assert.ok(realm.hasRole(account.principal, 'user'));
assert.ok(realm.hasRole(account.principal, 'admin'));
assert.equal(realm.hasRole(account.principal, 'dummy'), false);

assert.ok(realm.hasAllRoles(account.principal, ['admin', 'user']));
assert.equal(realm.hasAllRoles(account.principal, ['admin', 'user', 'dummy']), false);

var acs = [
    {
        url : '/admin',
        methods : 'GET, POST',
        authentication : 'BASIC',
        rules : '(([role=user] && [permission=admin]) || [role=admin])'
    },
    {
        url : '/products',
        methods : 'GET, POST',
        authentication : 'FORM',
        rules : '(([role=user] && [permission=products:{idProduct}]) || [role=admin])'
    }];

var acl = new security.AccessControlList();
utils.forEach(acs, function(accessControl){
    acl.store(accessControl);
});

var req = {
    url:'/admin', 
    method:'GET',
    signedCookies : [],
    cookies : []
};

var subject = new security.Subject(realm, req, false);
req.subject = subject;
subject.login(token);

var accessControl = acl.lookup(req);
assert.ok(utils.isDefined(accessControl));
assert.ok(accessControl.check(req));

req['url'] = '/products?idProduct=1';
accessControl = acl.lookup(req);
assert.ok(utils.isDefined(accessControl));
assert.ok(accessControl.check(req));

