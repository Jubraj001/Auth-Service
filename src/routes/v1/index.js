const express = require('express');
const UserController = require('../../controllers/user-controller');
const { AuthRequestValidators } = require('../../middlewares');

const router = express.Router();

router.post('/signup', AuthRequestValidators.validateUserAuth, UserController.create);
router.post('/signin', AuthRequestValidators.validateUserAuth, UserController.signIn);
router.post('/isAdmin', AuthRequestValidators.validateIsAdminRequest, UserController.isAdmin);
router.get('/isAuthenticated', UserController.isAuthenticated);

module.exports = router;
