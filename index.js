var request = require('request'),
    recaptchaKey = 'g-recaptcha-response',
    captchaRequiredFlag = 'captchaRequired';

var ensureCaptcha = function(config) {
  return function(req, res, next) {
    validate(config, req.body[recaptchaKey], function(err, success) {
      if(err) {
        next(err);
      } else if( ! success) {
        res.setBadRequest('server.error.badRecaptchaToken');
      } else {
        delete req.body[recaptchaKey];
        res.captcha = true;
        next();
      }
    });
  };
};

var ensureAdminOrCaptcha = function(config) {
  return function(req, res, next) {
    if(req.user && req.user.role && req.user.role.index == config.roles.admin) {
      next();
    } else {
      validate(config, req.body[recaptchaKey], function(err, success) {
        if(err) {
          next(err);
        } else if( ! success) {
          res.setBadRequest('server.error.badRecaptchaToken');
        } else {
          delete req.body[recaptchaKey];
          res.captcha = true;
          next();
        }
      });
    }
  };
};

var ensureLoginOrCaptcha = function(config) {
  return function(req, res, next) {
    if(req.user) {
      next();
    } else {
      validate(config, req.body[recaptchaKey], function(err, success) {
        if(err) {
          next(err);
        } else if( ! success) {
          next(new Error("Invalid captcha"));
        } else {
          delete req.body[recaptchaKey];
          res.captcha = true;
          next();
        }
      });
    }
  };
};

var checkLoginCaptcha = function(config) {
  return function(req, res, next) {
    var user = req.queriedUser;

    if(user.isLoginRecaptchaRequired()) {
      // Set the captcha required flag so the client knows
      // the next request made to this endpoint will require a captcha.
      res.setFlag(captchaRequiredFlag, true);

      validate(config, req.body[recaptchaKey], function(err, success) {
        if(err) {
          next(err);
        } else if( ! success) {
          //res.setFlag(captchaRequiredFlag, true);
          res.setBadRequest('server.error.badRecaptchaToken');
        } else {
          delete req.body[recaptchaKey];
          res.captcha = true;
          next();
        }
      });
    } else {
      next();
    }
  };
};

var validateRequest = function(config, req, res, next) {
  return validate(config, req.body[recaptchaKey], cb);
};

var validate = function(config, token, cb) {
  if( ! config) {
    config = require('../../config/index.js');
    if( ! config) {
      return cb(new Error('Configuration object is required.'));
    }
  }

  if( ! token) {
    return cb(undefined, false);
  }

  var options = {
    url: config.recaptcha.serverUrl,
    json: true,
    qs: {
      secret: config.recaptcha.serverKey,
      response: token
    }
  };

  if(config.recaptcha.enabled) {
    request.get(options, function(err, response, body) {
      if(err) {
        cb(err);
      } else if(body && body.success) {
        cb(undefined, true);
      } else {
        var i18n = require('i18next');
        err = new Error(i18n.t('server.error.invalidRecaptcha'));
        err.status = 400;
        cb(err);
      }
    });
  } else {
    cb(undefined, true);
  }
};

exports.validate = validate;
exports.validateRequest = validateRequest;
exports.checkLoginCaptcha = checkLoginCaptcha;
exports.ensureLoginOrCaptcha = ensureLoginOrCaptcha;
exports.ensureAdminOrCaptcha = ensureAdminOrCaptcha;
exports.ensureCaptcha = ensureCaptcha;
