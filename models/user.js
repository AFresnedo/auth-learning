'use strict';
var bcrypt = require('bcrypt');
module.exports = (sequelize, DataTypes) => {
  var user = sequelize.define('user', {
    firstname: DataTypes.STRING,
    lastname: DataTypes.STRING,
    email: {
      type: DataTypes.STRING,
      validate: {
        isEmail: {
          msg: 'Email must be a valid format.'
        }
      }
    },
    password: {
      type: DataTypes.STRING,
      validate: {
        len: {
          args: [6, 24],
          msg: 'Password must be between 6 and 24 characters long.'
        }
      }
    },
    image: {
      type: DataTypes.STRING,
      validate: {
        isUrl: {
          msg: 'Img link must be a valid URL.'
        }
      }
    },
    facebookId: DataTypes.STRING,
    facebookToken: DataTypes.STRING,
    admin: DataTypes.BOOLEAN
  }, {
    hooks: {
      beforeCreate: function(pendingUser) {
        if (pendingUser && pendingUser.password) {
          var hash = bcrypt.hashSync(pendingUser.password, 10);
          pendingUser.password = hash;
        }
      }
    }
  });
  user.associate = function(models) {
    // associations can be defined here
  };

  // helpers go here, after ^ stuff and before return
  user.prototype.isValidPassword = function(typedPassword) {
    return bcrypt.compareSync(typedPassword, this.password);
  };

  return user;
};
