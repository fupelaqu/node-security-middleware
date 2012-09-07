var mongoose = require('mongoose')
, Schema = mongoose.Schema
, utils = require('security-middleware/lib/utils.js')
, credentialsMatcher = require('security-middleware/lib/security.js').sha256CredentialsMatcher
, encryptedPassword = credentialsMatcher.encrypt('changeit');

var conn = mongoose.createConnection('localhost', 'test');

conn.on('error', console.error.bind(console, 'connection error:'));

var RoleTypes = 'user admin'.split(' ');

var roleSchema = new Schema(
  {
      name: { 
          'type': String, 
          'enum': RoleTypes,
          index : true
      },
      privileges : [String]
  }
);

mongoose.model('Role', roleSchema);

var userSchema = new Schema(
    { 
        login: { 
            'type': String, 
            index : true
        }, 
        password: String, 
        roles: [{ 
            'type' : String, 
            'enum' : RoleTypes 
        }], 
        privileges : [String]
    }
);

mongoose.model('User', userSchema);

conn.once('open', function () {

    var Role = conn.model('Role');
    utils.forEach(RoleTypes, function(role){
        Role.findOne({
            name : role
        }, 'name', {}, function(err, doc){
            if(err){
                console.error(err);
            }
            else if(!doc){
                var _role = new Role({
                    name : role,
                    privileges : 'admin' === role ? 'admin:*' : ''
                });
                _role.save(function(err){
                    if(err){
                        console.error(err);
                    }
                });
            }
            else{
                console.log('Role ' + doc.name + ' already exists');
            }
        });
    });

    var User = conn.model('User');
    User.findOne({
        login:'admin'
    }, 'login', {}, function(err, doc){
        if(err){
            console.error(err);
        }
        else if(!doc){
            var _account = new User({
                login : 'admin',
                password : encryptedPassword,
                roles : ['user', 'admin']
            });
            _account.save(function(err){
                if(err){
                    console.error(err);
                }
            });
        }
        else{
            console.log('User admin already exists');
        }
    });
    User.findOne({
        login:'user'
    }, 'login', {}, function(err, doc){
        if(err){
            console.error(err);
        }
        else if(!doc){
            var _account = new User({
                login : 'user',
                password : encryptedPassword,
                roles : ['user'],
                privileges : [ 'products:company_1:list', 'products:company_1:show' ]
            });
            _account.save(function(err){
                if(err){
                    console.error(err);
                }
            });
        }
        else{
            console.log('User user already exists');
        }
    });

    console.log('db connection opened');
});

var Store = function(){
    var self = this;
    conn.on('open', function () {
        self.Role = conn.model('Role');
        self.User = conn.model('User');
        console.log('Store initialized');
    });
};

/**
 * Returns the user mapped to this username or null
 * 
 * If exists, the returned object should include the user's password
 * 
 * @param username
 * @returns the user mapped to this username or null
 */
Store.prototype.lookup = function(username, callback) {
    this.User.findOne({
        login:username
    }, 'login password', {}, function(err, doc){
        if(err){
            callback(err);
        }
        else if(doc){
            callback(null, {
                username : doc.login, 
                password : doc.password
            });
        }
        else{
            callback();
        }
    });
};

/**
 * Returns the roles granted to the user mapped to this username as an array of string
 * 
 * @param username
 * @returns the roles granted to the user mapped to this username as an array of string
 */
Store.prototype.loadUserRoles = function(username, callback) {
    this.User.findOne({
        login:username
    }, 'roles', {}, function(err, doc){
        if(err){
            callback(err);
        }
        else if(doc){
            var roles = doc.roles;
            callback(null, roles);
        }
        else{
            callback();
        }
    });
};

/**
 * Returns the privileges granted to the user mapped to this username as an array of string
 * 
 * @param username
 * @returns the privileges granted to the user mapped to this username as an array of string
 */
Store.prototype.loadUserPrivileges = function(username, callback) {
    this.User.findOne({
        login:username
    }, 'privileges', {}, function(err, doc){
        if(err){
            callback(err);
        }
        else if(doc){
            var privileges = doc.privileges;
            callback(null, privileges);
        }
        else{
            callback();
        }
    });
};

/**
 * Returns the privileges granted to the role mapped to this role name as an array of string
 * 
 * @param roleName
 * @returns the privileges granted to the role mapped to this role name as an array of string
 */
Store.prototype.loadRolePrivileges = function(roleName, callback) {
    this.Role.findOne({
        name : roleName
    }, 'privileges', {}, function(err, doc){
        if(err){
            callback(err);
        }
        else if(doc){
            var privileges = doc.privileges;
            callback(null, privileges);
        }
        else{
            callback();
        }
    });
};

exports.Store = Store;
