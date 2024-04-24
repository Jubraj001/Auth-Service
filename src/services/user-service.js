const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const UserRepository = require("../repository/user-repository");
const { JWT_KEY } = require('../config/serverConfig');
const AppErrors = require('../utils/error-handler');

class UserService {
  constructor() {
    this.userRepository = new UserRepository();
  }

  async create(data) {
    try {
      const user = await this.userRepository.create(data);
      return user;
    } catch (error) {
      console.log(error)
      if(error.name === 'SequelizeValidationError') {
        throw error;
      }
      throw new AppErrors(
        'ServerError',
        'Something went wrong in service',
        'Logical issue found',
        500
      );
    }
  }

  async signIn(email, plainPassword) {
    try {
      const user = await this.userRepository.getByEmail(email);
      const passwordMatch = this.checkPassword(plainPassword, user.password);
      if(!passwordMatch) {
        console.log('Password does not match!');
        throw { error: 'Incorrect Password' };
      }
      const newJwt = this.createToken({ email: user.email, id: user.id });
      return newJwt;
    } catch (error) {
      if(error.name === 'AttributeNotFound') {
        throw error;
      }
      console.log('Something went wrong on repository layer');
      throw error;
    }
  }

  async isAuthenticated(token) {
    try {
      const response = this.verifyToken(token);
      if(!response) {
        throw { error: 'Invalid Token' };
      }
      const user = await this.userRepository.getById(response.id);
      if(!user) {
        throw { error: 'No user with corresponding id exists' };
      }
      return user.id;
    } catch (error) {
      console.log('Something went wrong on repository layer');
      throw error;
    }
  }

  createToken(user) {
    try {
      const result = jwt.sign(user, JWT_KEY, { expiresIn: '1h' });
      return result;
    } catch (error) {
      console.log('Something went wrong in token creation');
      throw error;
    }
  }

  verifyToken(token) {
    try {
      const result = jwt.verify(token, JWT_KEY);
      return result;
    } catch (error) {
      console.log('Something went wrong in token validation');
      throw error;
    }
  }

  checkPassword(userInputPassword, encryptedPassword) {
    try {
      return bcrypt.compareSync(userInputPassword, encryptedPassword);
    } catch (error) {
      console.log('Something went wrong in password comparison');
      throw error;
    }
  }

  isAdmin(userId) {
    try {
      return this.userRepository.isAdmin(userId);
    } catch (error) {
      console.log('Something went wrong in service layer');
      throw error;
    }
  }
}

module.exports = UserService;
