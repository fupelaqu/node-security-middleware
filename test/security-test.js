/* 
 * security unit tests.
 * 
 */

var security = require('../lib/security.js'), crypto = require('crypto'), utils = require('../lib/utils.js');

exports['test security.CredentialsMatcher#doCredentialsMatch'] = function(
        beforeExit, assert) {
    var password = 'changeit';
    var token = new security.UsernamePasswordToken('test', password, true);
    assert.equal(true, utils.every([ 'md5', 'sha1', 'sha256', 'sha512' ],
            function(algorithm) {
                return new security.CredentialsMatcher(algorithm)
                        .doCredentialsMatch(token, {
                            credentials : crypto.createHash(algorithm).update(
                                    password).digest('hex')
                        });
            }));
};

exports['test security.UsernamePasswordToken'] = function(beforeExit, assert) {
    var usernamePasswordToken = new security.UsernamePasswordToken();

    assert.equal(true, utils.isDefined(usernamePasswordToken));
    assert.equal(true, utils.isDefined(usernamePasswordToken.getUsername));
    assert.equal(true, utils.isDefined(usernamePasswordToken.getPrincipal));
    assert.equal(true, utils.isDefined(usernamePasswordToken.getPassword));
    assert.equal(true, utils.isDefined(usernamePasswordToken.getCredentials));
    assert.equal(true, utils.isDefined(usernamePasswordToken.isRememberMe));
    assert.equal(false, usernamePasswordToken.isRememberMe());

    usernamePasswordToken = new security.UsernamePasswordToken('test',
            'changeit', true);

    assert.equal('test', usernamePasswordToken.getUsername());
    assert.equal('test', usernamePasswordToken.getPrincipal());
    assert.equal(true, utils.isEqual(utils.toCharArray('changeit'),
            usernamePasswordToken.getPassword()));
    assert.equal('changeit', usernamePasswordToken.getCredentials());
    assert.equal(true, usernamePasswordToken.isRememberMe());
};

var credentialsMatcher = security.sha256CredentialsMatcher;

var store = security.inMemoryStore;

store.storeRole({
    name : 'user',
    privileges : []
});

var adminRolePrivileges = [ 'admin:*' ];

store.storeRole({
    name : 'admin',
    privileges : adminRolePrivileges
});

var userRoles = [ 'user' ];

var userPrivileges = [ 'products:company_1:list', 'products:company_1:show:*' ];

store.storeAccount({
    username : 'user',
    password : credentialsMatcher.encrypt('changeit'),
    roles : userRoles,
    privileges : userPrivileges
});

var adminRoles = [ 'user', 'admin' ];

var adminPrivileges = [];

store.storeAccount({
    username : 'admin',
    password : credentialsMatcher.encrypt('changeit'),
    roles : adminRoles,
    privileges : adminPrivileges
});

exports['test security.InMemoryStore'] = function(beforeExit, assert) {
    assert.equal(true, utils.isDefined(store));

    store.lookup('user', function(err, user){
        assert.equal(true, utils.isDefined(user));
    });

    store.loadUserRoles('user', function(err, roles){
        assert.equal(true, utils.isEqual(userRoles, roles));
    });

    store.lookup('admin', function(err, admin){
        assert.equal(true, utils.isDefined(admin));
    });

    store.loadUserRoles('admin', function(err, roles){
        assert.equal(true, utils.isEqual(adminRoles, roles));
    });

    store.loadRolePrivileges('admin', function(err, privileges){
        assert.equal(true, utils.isEqual(adminRolePrivileges, privileges));
    });

};

var realmName = 'Security';

var realm = new security.Realm({
    realmName : realmName,
    credentialsMatcher : 'sha256'
});

var principal = 'admin';

var token = new security.UsernamePasswordToken(principal, 'changeit');

exports['test security.Realm'] = function(beforeExit, assert) {
    assert.equal(true, utils.isDefined(realm));

    assert.equal(realmName, realm.name);

    assert.equal(security.sha256CredentialsMatcher, realm.credentialsMatcher);

    realm.authenticate(token, function(err, account){
        assert.equal(true, utils.isDefined(account));
        assert.equal(true, utils.isEqual(principal, account.principal));
    });

    realm.hasRole(principal, 'user', function(err, value){
        assert.equal(true, value);
    });
    realm.hasRole(principal, 'admin', function(err, value){
        assert.equal(true, value);
    });
    realm.hasRole(principal, 'dummy', function(err, value){
        assert.equal(false, value);
    });

    realm.hasAllRoles(principal, [ 'admin', 'user' ], function(err, value){
        assert.equal(true, value);
    });
    realm.hasAllRoles(principal, [ 'admin', 'user', 'dummy' ], function(err, value){
        assert.equal(false, value);
    });

    realm.isPermitted(principal, 'admin:user:add', function(err, value){
        assert.equal(true, value);
    });
    realm.isPermitted(principal, 'admin:user:*', function(err, value){
        assert.equal(true, value);
    });
    realm.isPermitted(principal, 'admin:*', function(err, value){
        assert.equal(true, value);
    });
    realm.isPermitted(principal, 'dummy', function(err, value){
        assert.equal(false, value);
    });
    realm.isPermitted(principal, '*', function(err, value){
        assert.equal(false, value);
    });
};

exports['test security.AccessControlList'] = function(beforeExit, assert) {
    var acs = [
            {
                url : '/admin',
                methods : 'GET, POST',
                authentication : 'BASIC',
                rules : '(([role=user] && [permission=admin]) || [role=admin])'
            },
            {
                url : '/products/list',
                methods : 'GET',
                authentication : 'FORM',
                rules : '(([role=user] && [permission=products:company_{idCompany}:list]) || [role=admin])'
            },
            {
                url : '/products',
                methods : 'GET',
                authentication : 'FORM',
                rules : '(([role=user] && [permission=products:company_{idCompany}:show:product_{idProduct}]) || [role=admin])'
            },
            {
                url : '/products',
                methods : 'PUT',
                authentication : 'FORM',
                rules : '(([role=user] && [permission=products:company_{idCompany}:create]) || [role=admin])'
            },
            {
                url : '/products',
                methods : 'POST',
                authentication : 'FORM',
                rules : '(([role=user] && [permission=products:company_{idCompany}:update]) || [role=admin])'
            },
            {
                url : '/products',
                methods : 'DELETE',
                authentication : 'FORM',
                rules : '(([role=user] && [permission=products:company_{idCompany}:delete]) || [role=admin])'
            }

    ];

    var acl = new security.AccessControlList();
    utils.forEach(acs, function(accessControl) {
        acl.store(accessControl);
    });

    var req = {
        url : '/admin',
        method : 'GET',
        signedCookies : [],
        cookies : []
    };

    var subject = new security.Subject(realm, req, null, false);
    req.subject = subject;
    subject.login(token, function(err, value){
        assert.equal(true, utils.isUndefined(err));
    });

    var accessControl = acl.lookup(req);
    assert.equal(true, utils.isDefined(accessControl));
    accessControl.check(req, function(err, value){
        assert.equal(true, utils.isUndefined(err));
        assert.equal(true, value);
    });

    req['url'] = '/products/list?idCompany=1';
    accessControl = acl.lookup(req);
    assert.equal(true, utils.isDefined(accessControl));
    accessControl.check(req, function(err, value){
        assert.equal(true, utils.isUndefined(err));
        assert.equal(true, value);
    });

    req['url'] = '/products?idCompany=1&idProduct=1';
    accessControl = acl.lookup(req);
    assert.equal(true, utils.isDefined(accessControl));
    accessControl.check(req, function(err, value){
        assert.equal(true, utils.isUndefined(err));
        assert.equal(true, value);
    });

    req['url'] = '/products?idCompany=1';
    req['method'] = 'PUT';
    accessControl = acl.lookup(req);
    assert.equal(true, utils.isDefined(accessControl));
    accessControl.check(req, function(err, value){
        assert.equal(true, utils.isUndefined(err));
        assert.equal(true, value);
    });

    req['method'] = 'POST';
    req['body'] = {
        idCompany : 1
    };
    accessControl = acl.lookup(req);
    assert.equal(true, utils.isDefined(accessControl));
    accessControl.check(req, function(err, value){
        assert.equal(true, utils.isUndefined(err));
        assert.equal(true, value);
    });

    req['method'] = 'DELETE';
    accessControl = acl.lookup(req);
    assert.equal(true, utils.isDefined(accessControl));
    accessControl.check(req, function(err, value){
        assert.equal(true, utils.isUndefined(err));
        assert.equal(true, value);
    });

    subject.logout();

    req = {
        url : '/admin',
        method : 'GET',
        signedCookies : [],
        cookies : []
    };
    subject = new security.Subject(realm, req, null, false);
    req.subject = subject;
    subject.login(new security.UsernamePasswordToken('user', 'changeit'));

    accessControl = acl.lookup(req);
    assert.equal(true, utils.isDefined(accessControl));
    accessControl.check(req, function(err, value){
        assert.equal(true, utils.isUndefined(err));
        assert.equal(false, value);
    });

    req['url'] = '/products/list?idCompany=1';
    accessControl = acl.lookup(req);
    assert.equal(true, utils.isDefined(accessControl));
    accessControl.check(req, function(err, value){
        assert.equal(true, utils.isUndefined(err));
        assert.equal(true, value);
    });

    req['url'] = '/products?idCompany=1&idProduct=1';
    accessControl = acl.lookup(req);
    assert.equal(true, utils.isDefined(accessControl));
    accessControl.check(req, function(err, value){
        assert.equal(true, utils.isUndefined(err));
        assert.equal(true, value);
    });

    req['url'] = '/products?idCompany=1';
    req['method'] = 'PUT';
    accessControl = acl.lookup(req);
    assert.equal(true, utils.isDefined(accessControl));
    accessControl.check(req, function(err, value){
        assert.equal(true, utils.isUndefined(err));
        assert.equal(false, value);
    });

    req['method'] = 'POST';
    req['body'] = {
        idCompany : 1
    };
    accessControl = acl.lookup(req);
    assert.equal(true, utils.isDefined(accessControl));
    accessControl.check(req, function(err, value){
        assert.equal(true, utils.isUndefined(err));
        assert.equal(false, value);
    });

    req['method'] = 'DELETE';
    accessControl = acl.lookup(req);
    assert.equal(true, utils.isDefined(accessControl));
    accessControl.check(req, function(err, value){
        assert.equal(true, utils.isUndefined(err));
        assert.equal(false, value);
    });
};
