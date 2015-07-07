var request = require('request'),
    async = require('async'),
    recaptchaKey = 'g-recaptcha-response',
    defaultTokenLocation = 'body.' + recaptchaKey,
    serverUrl = 'https://www.google.com/recaptcha/api/siteverify';

var ensureCaptcha = function(options) {
  return function(req, res, next) {
    parseAndValidateCaptcha(req, res, next, options);
  };
};

var ensureLoginOrCaptcha = function(options) {
  return function(req, res, next) {
    if(req.user) {
      next();
    } else {
      parseAndValidateCaptcha(req, res, next, options);
    }
  };
};

/**
 * Validates a ReCATPCHA token using Google's API.
 * @param options An object containing configuration options.
 * @param {string} options.serverKey (Required) is the secret key shared between the site and Google's reCAPTCHA.
 * @param {string} options.serverUrl is the URL where the ReCAPTCHA is validated. This defaults to Google's API.
 * @param {string} token is the ReCAPTCHA token received from the client.
 * @param cb
 * @returns {*}
 */
var validate = function(options, token, cb) {
  if(!options || !options.serverKey) {
    return cb(new Error('options with an options.serverKey is required.'));
  }

  if(!token) {
    return cb(undefined, false);
  }

  var requestOptions = {
    url: options.serverUrl || serverUrl,
    json: true,
    qs: {
      secret: options.serverKey,
      response: token
    }
  };

  request.get(requestOptions, function(err, response, body) {
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
};

/* ************************************************** *
 * ******************** Helper functions
 * ************************************************** */

/**
 * Parses the ReCAPTCHA token from the express request object and validates it.
 * @param req is the express request object.
 * @param res is the express response object.
 * @param next is the
 * @param {object} options is an object containing configuration options.
 */
function parseAndValidateCaptcha(req, res, next, options) {
  async.waterfall([
      function(callback) {
        parseClientToken(req, defaultTokenLocation || options.recaptchaLocation, function(err, token) {
          return callback(err, token);
        })
      },
      function(token, callback) {
        validate(options, token, function(err, success) {
          return callback(err, success);
        });
      }
    ],
    function(err, success) {
      if(err) {
        next(err);
      } else if( ! success) {
        res.setBadRequest('server.error.badRecaptchaToken');
      } else {
        delete req.body[recaptchaKey];
        res.captcha = true;
        next();
      }
    })
}

/**
 * Parses the ReCAPTCHA token from the client's request.
 * @param {object} req is the express request object.
 * @param {string} recaptchaLocation is the string representation of the location of the ReCaptcha token within the request object. E.g. 'body.recpatchaToken'
 * @param cb
 */
function parseClientToken(req, recaptchaLocation, cb) {
  getPropertyByString(req, recaptchaLocation, function(err, clientToken) {
    cb(err, clientToken);
  });
}

/**
 * Retrieves an objects property value using a string like 'body.username'
 * @param {object} obj is the object that contains the property that will be searched for.
 * @param {string} str is the string indicating what property to search for. E.g. 'user.location.country'
 * @param callback
 * @returns {*}
 */
function getPropertyByString(obj, str, callback) {
  str = str.replace(/\[(\w+)\]/g, '.$1'); // convert indexes to properties
  str = str.replace(/^\./, '');           // strip a leading dot
  var a = str.split('.');
  for (var i = 0, n = a.length; i < n; ++i) {
    var k = a[i];
    if (k in obj) {
      obj = obj[k];
    } else {
      if(typeof callback === 'function') {
        return callback();
      } else {
        return;
      }
    }
  }

  if(typeof callback === 'function') {
    return callback(undefined, obj);
  } else {
    return obj;
  }
}

/* ************************************************** *
 * ******************** Exports
 * ************************************************** */

exports.validate = validate;
exports.ensureLoginOrCaptcha = ensureLoginOrCaptcha;
exports.ensureCaptcha = ensureCaptcha;
