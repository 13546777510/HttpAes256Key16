var exec = require('cordova/exec');

exports.coolMethod = function (arg0, success, error) {
    exec(success, error, 'HttpAes256Key16', 'coolMethod', [arg0]);
};

//加密
exports.Encrypt = function (key, iv, data, success, error) {
  exec(success, error, 'HttpAes256Key16', 'Encrypt', [key, iv, data]);
};

//解密
exports.Decrypt = function (key, iv, data, success, error) {
  exec(success, error, 'HttpAes256Key16', 'Decrypt', [key, iv, data]);
};
