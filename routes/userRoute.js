const express = require('express');
const router = express.Router();
const path = require("path");
const { body} = require('express-validator');
const userController = require('../controllers/userController');


router.post('/signup',[

  body('username').exists().withMessage('name is required'),
  body('password').exists().withMessage('Password is required'),
  body('email').exists().withMessage('email is required'),
  ],
  userController.signup
  )
router.post('/login',
  [
    body('email').exists().withMessage('email is required'),
    body('password').exists().withMessage('Password is required'),
  ],
 
  userController.login
);


router.post('/password/reset',
  [
    body("email").exists().withMessage("email is required"),
    body("password").exists().withMessage("New password is required"),
  ],
  userController.resetPassword
);
router.get('/password/reset/verify',
  userController.resetPasswordVerify
);
router.get('/resetPassword',(req,res)=>{

  const filePath = path.join(__dirname, '../public/resetPassword.html');
  res.sendFile(filePath);
}
  
);

router.get('/email/verify',
userController.verifySave
);

module.exports = router;