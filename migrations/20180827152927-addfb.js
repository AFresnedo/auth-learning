'use strict';

module.exports = {
  up: (queryInterface, Sequelize) => {
    return queryInterface.addColumn('users', 'facebookId', Sequelize.STRING)
      .then(function() {
        return queryInterface.addColumn('users', 'facebookToken',
          Sequelize.STRING);
      });
  },

  down: (queryInterface, Sequelize) => {
    return queryInterface.removeColumn('users', 'facebookId')
      .then(function() {
        return queryInterface.removeColumn('users', 'facebookToken');
      });;
  }
};
