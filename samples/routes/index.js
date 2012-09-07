
/*
 * GET home page.
 */

exports.index = function(req, res){
  res.render('index', { title: 'Express Security' });
};

exports.admin = function(req, res){
  res.render('admin', { title: 'Express Security Administration' });
};

exports.login = function(req, res){
  res.render('login', { username: req.param('username'), redirect : req.param('redirect') });
};

exports.products = function(req, res){
  res.render('products', { title: 'Express Security Products' });
};

