const Promise = require('bluebird');
const rfc2253 = require('rfc2253');
const LdapAuth = require('ldapauth-fork');

Promise.promisifyAll(LdapAuth.prototype);

function Auth(config, stuff) {
  const self = Object.create(Auth.prototype);
  self._users = {};

  // config for this module
  self._config = config;

  // verdaccio logger
  self._logger = stuff.logger;

  // pass verdaccio logger to ldapauth
  self._config.client_options.log = stuff.logger;

  self.cacheTime = config.cacheTime || 1000 * 60 * 3;

  // TODO: Set more defaults
  self._config.groupNameAttribute = self._config.groupNameAttribute || 'cn';

  return self;
}

module.exports = Auth;

//
// Attempt to authenticate user against LDAP backend
//
Auth.prototype.authenticate = function (user, password, callback) {
  const LdapClient = new LdapAuth(this._config.client_options);

  // https://github.com/vesse/node-ldapauth-fork/issues/61
    LdapClient.on('error', (err) => {
        this._logger.error({err}, `Ldap --- ldapClient is crash, ${err}`);
    });

    const cacheUser = this.getCacheUser(user);
    if(cacheUser) {
        this._logger.trace({
            user,
            cacheUser,
        }, `Ldap --- find out cache user: ${user}`);
        return callback(null, [
            cacheUser.cn,
            ...cacheUser._groups ? [].concat(cacheUser._groups).map((group) => group.cn) : [],
            ...cacheUser.memberOf ? [].concat(cacheUser.memberOf).map((groupDn) => rfc2253.parse(groupDn).get('CN')) : [],
        ]);
    }

    this._logger.trace({
        user
    }, `Ldap --- miss cache user: ${user}`);

    this._logger.trace({
        user: user
    }, `Ldap --- user:${user} generate a request ti ldap server to authenticate`);

  LdapClient.authenticateAsync(user, password)
    .then((ldapUser) => {
      if (!ldapUser) return [];

      this.setCacheUser(user, ldapUser);

      return [
        ldapUser.cn,
        // _groups or memberOf could be single els or arrays.
        ...ldapUser._groups ? [].concat(ldapUser._groups).map((group) => group.cn) : [],
        ...ldapUser.memberOf ? [].concat(ldapUser.memberOf).map((groupDn) => rfc2253.parse(groupDn).get('CN')) : [],
      ];
    })
    .catch((err) => {
      // 'No such user' is reported via error
      this.removeCacheUser(user);
      this._logger.warn({
        user: user,
        err: err,
      }, `LDAP error ${err}`);

      return false; // indicates failure
    })
    .finally((ldapUser) => {
      LdapClient.closeAsync()
        .catch((err) => {
          this._logger.warn({
            err: err
          }, `LDAP error on close ${err}`);
        });
      return ldapUser;
    })
    .asCallback(callback);
};

Auth.prototype.getCacheUser = function (key) {
    const cacheUser = this._users[key];
    if(!cacheUser) {
        return null;
    }
    if(Date.now() > cacheUser.expiredTime) {
        this._logger.trace({
            user: key
        }, `Ldap --- user: ${key} is outed of expiredTime`);
        this.removeCacheUser(key);
        return null;
    }
    return cacheUser.data;
};

Auth.prototype.setCacheUser = function (key, data) {
    this._logger.trace({
        user: key,
        data
    }, `Ldap cache set: ${key}`);
    const cacheUser = {
        data,
        expiredTime: Date.now() + this.cacheTime
    };
    this._users[key] = cacheUser;
};

Auth.prototype.removeCacheUser = function (key) {
    this._logger.trace({
        user: key
    }, `Ldap --- remove cache user: ${key}`);
    delete this._users[key];
};
