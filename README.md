# Back-end

The back-end is completely contained within the *functions* folder.  This is the folder Netlify uses to compile it's lambda functions for deployment.

The structure of this folder is as follows:
* **connectDB**: Houses main module for MongoDB initialization.
* **controllers**: All logic for API operations.
* **middleware**: Custom middleware functions.
* **models**: Mongoose schema's for DB collection items.
* **routes**: All route modules that call route controllers.

> **Note**: The main *server.js* file is responsible for initiating the MongoDB connection, establishing global back-end middleware and defining main API routes.
> *connect.DB/db.js* is where your *REACT_APP_MONGO_URI* is used.

If you need to add a new main route, add a new route in the `// Define routes` section, following the same format as the existing base routes.
The following is in *server.js*.
```javascript
const connectDB = require('./connectDB/db');
const express = require('express');
const serverless = require('serverless-http');
const cors = require('cors');
const app = express();

const { REACT_APP_API_V1: v1 } = process.env;

app.set('trust proxy', 1);

// Connect database
connectDB();

// Init middleware
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cors());

// Define routes
app.use(`${v1}sample`, require('./routes/sampleRoutes'));
app.use(`${v1}email`, require('./routes/emailRoutes'));
app.use(`${v1}auth`, require('./routes/authRoutes'));

app.keepAliveTimeout = 121 * 1000;
app.headersTimeout = 125 * 1000;

module.exports.handler = serverless(app);
```

## About API Versioning
Since the version number is attached to the base path *REACT_APP_API_V1* variable, you have modular control over API versioning, so you don't
break existing API versions still in production.  For new versions, add a new env variable with the new API version in the name and value:
```javascript
REACT_APP_API_V2="/.netlify/functions/server/v2/"
REACT_APP_API_V1="/.netlify/functions/server/v1/"
```

Then import it for use in *server.js*.
```javascript
const {
  REACT_APP_API_V2: v2,
  REACT_APP_API_V1: v1,
} = process.env;

// v2 routes
app.use(`${v2}sample`, require('./routes-v2/sampleRoutes'));
app.use(`${v2}auth`, require('./routes-v2/authRoutes'));

// v1 routes
app.use(`${v1}sample`, require('./routes/sampleRoutes'));
app.use(`${v1}auth`, require('./routes/authRoutes'));
```

## About Routes
> Routes are imported and used on the base endpoints established in *server.js*

Although the main endpoint is defined in *server.js*, each subsequent route path for that endpoint is defined in the routes folder.
If you need more routes, copy the *routes/sampleRoutes.js* file and work from there.  Remember to import this new route module in *server.js*.

The following can be found in *sampleRoutes.js*:
```javascript
const express = require('express');
const router = express.Router();
const limiter = require('../middleware/limitMiddleware');

const {
  getSample,
  postSample,
  putSample,
  deleteSample
} = require('../controllers/sampleController');

// Caching
const apicache = require('apicache');
let cache = apicache.middleware;
const defaultCache = '2 minutes';

// Starter routes
router.route('/')
  .get(limiter(), cache(defaultCache), getSample)
  .post(limiter(), cache(defaultCache), postSample);


router.route('/:id')
  .put(limiter(), cache(defaultCache), putSample)
  .delete(limiter(), cache(defaultCache), deleteSample);

module.exports = router;
```

Express' `router.route()` method is a clean way to consolidate identical route paths for an endpoint. It saves a few lines of code and minimizes any chance
of errors from typing the same route string over and over. As noted in their documentation, middlewares for each route type defined like this should be
placed before the controller function is called, as shown above, **not** where the route is defined.

## About Middleware
> All custom back-end middleware functions should be kept in the *functions/middleware* folder.

Consider the following in *routes/sampleRoutes.js*:
```javascript
// Starter routes
router.route('/')
  .get(limiter(), cache(defaultCache), getSample)
  .post(limiter(), cache(defaultCache), postSample);
```

Instead of defining the middleware for the entire server, as is the case with `app.use(cors())` and others (in *server.js*), we can inject them on a
per route basis for modular control. In the above example, `limiter()` and `cache()` are examples of per-route middleware.  Doing it this way allows for much
finer control over whether you want a route to be exempt from rate limiting, caching or other middleware you may have.  Furthermore, it allows you to customize
the same middlware function, differently, for each individual route &mdash; so rate limits, for example, can be different from one route to another.

### About the limiter() middleware
The default `express-rate-limit` middleware has been expanded in this implementation to be fully customizable.  `limiter()` takes four arguments:
`limiter(maxNumOfReqs, timeInMilliseconds, "Your custom message", "objKeyName")`.  Your custom message will interface with the front-end notification system when a 429 is returned.  If using an object, the front-end notification system will need either a single string (shown previously) or an object with the following keys:
```javascript
const message = {
  message: "My custom message string.",
  icon: "fa-solid fa-check" // Font Awesome icon
  type, // "success", "warning" or "error" Override for notification type on the front end
}
```

There is also a middleware handler within the `limiter()` responsible for returning the 429 status, your message (if provided) and this handler can also
be used for more advanced functionality such as charging user fees prior to cutting them off etc.

> Rate limiting is done by IP address by default, but can be changed in the `keyGenerator` to use user ID.

The following can be found in *middleware/limitMiddleware.js*:
```javascript
const { rateLimit } = require('express-rate-limit');

const limiter = (max, windowMs, message, keyName) => rateLimit({
  max: max || 2,
  windowMs: windowMs || 5000,
  keyGenerator: (req, res) => req.ip,
  handler: (req, res, next) => {
    res.status(429).json({
      [keyName || "error"]: message || "Too many requests.",
    });

    next();
  }
});

module.exports = limiter;
```

### About the auth() middleware
The `auth()` middleware is responsible for validating token data in the request header.  If the token is valid, it runs `next()`, otherwise it stops
access to the private route.  You will need to provide the `x-auth-token` header with the value set to the user's token when accessing a private route.

The following can be found in *middleware/authMiddleware.js*:
```javascript
const jwt = require('jsonwebtoken');

require('dotenv').config();
const { REACT_APP_JWT_SECRET: jwtSecret } = process.env;

module.exports = function(req, res, next) {
  const token = req.header('x-auth-token');

  if (!token) {
    return res.status(401).json({ error: 'Unauthorized: No token found.' });
  };

  try {
    const decoded = jwt.verify(token, jwtSecret);
    req.user = decoded.user;
    next();
  } catch(err) {
    res.status(401).json({ error: 'Invalid token.' });
  };
};
```



## About Controllers
> All controllers should be kept in the *controllers* folder and are imported for use in your *routes* file.

Controllers extract all logic from your *routes* file to keep the *routes* file exclusively about routing.

Consider the following controller in *controllers/sampleController.js*:
```javascript
// @access  Public
// @route   GET server/v1/sample
// @desc    API test response endpoint.
const getSample = async (req, res) => {
  try {
    res.status(200).json({ message: message("GET") });
  } catch(error) {
    res.status(500).json({ error });
  }
};
```

A simple function that handles what happens when the *server/v1/sample* endpoint is hit.  It's a good idea to include information about each
controller as shown above.

## About Models
Mongoose is the primary library used for creating back-end models, as well as interacting with your DB.

The following can be found in *models/userModel.js*:
```javascript
const mongoose = require('mongoose');
const moment = require('moment');

const UserSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
    },

    password: {
      type: String,
      required: true,
    },

    agreedTo: {
      type: Array,
      required: true,
    }
  },
  {
    timestamps: true
  }
);

module.exports = User = mongoose.model('user', UserSchema);
```

This example shows a new user schema that includes a unique `email` entry in the database and a `password` entry that will be used to store
hashed password data. `created_at` and `updated_at` are automatically added with the `{ timestamps: true }` object.  You can see how this is called
and used in *controllers/authController.js*



## Authentication and User Routes
Authentication is handled via the following routes:
* `GET`, `POST` on `/auth`.
* `POST`, `PUT`, `DELETE` on `/users`.
* `POST` on `/users/me`.
* `POST` on `/emails/pw-reset`.

Authentication and user routes are defined in `functions/server.js`:
```javascript
app.use(`${v1}auth`, require('./routes/authRoutes'));
app.use(`${v1}users`, require('./routes/userRoutes'));
app.use(`${v1}emails`, require('./routes/emailRoutes'));
```

The following is found in `functions/routes/authRoutes.js`:
```javascript
router.route('/')
  .get(limiter(), auth, getUserData)
  .post(limiter(), checkLoginPayload, login);
```

The following is found in `functions/routes/userRoutes.js`:
```javascript
router.route('/me')
  .post(limiter(), checkTokenPayload, checkToken);

router.route('/')
  .post(limiter(), checkCreateUserPayload, createUser)
  .put(limiter(), auth, checkUpdateUserPayload, updateUser)
  .delete(limiter(), auth, checkDeleteUserPayload, deleteUser);
```

The following is found in `functions/routes/emailRoutes.js`:
```javascript
router.route('/pw-reset')
  .post(limiter(), checkResetReqPayload, sendResetReq);
```

All route logic can be found in `functions/controllers/authController.js`, `functions/controllers/userController.js` and `functions/controllers/emailController.js` (for password reset), as far as actual API call logic goes.



### Creating a user
User creation can be done by sending a `POST` request to `/users` with a JSON body that includes the following:

```json
{
  "email": "username@servicedomain.ext",
  "password": "Secure User P@ssword123",
  "confirmPassword": "Secure User P@ssword123",
  "trustedDevice": true
}
```

A response will be sent for valid requests that will include a new JWT token for that user, including the user, when their session ends and a message — for further use on the front-end:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7ImlkIjoiNjMxNGMxNDY5ODllYzNmMzlhOGFkNjY2In0sImlhdCI6MTY2MjMwNDU4MiwiZXhwIjoxNjY0ODk2NTgyfQ.rWmExtNh4Z1WA37Tni-kJ-ThE4zff2jYNpGOxJHjgWw",
  "user": "username@servicedomain.ext",
  "sessionEnd": 1664896582,
  "message": "Account created. Welcome!"
}
```

**Note**: For security, a generic error message is sent if the user is not able to be created for **any** reason, server or otherwise.



### Getting user data
Once at least one user has been created, user data can be called by sending a `GET` request to `/auth`

> This is a private route that will require a valid token in the request header: `x-auth-token: ${token}`.

A response will be sent for valid requests that will include the following user information:

```json
{
  "_id": "624c337c0f08e2f4659bd8cf",
  "email": "username@servicedomain.ext",
  "createdAt": "2022-04-05T12:18:05.340Z",
  "updatedAt": "2022-09-04T15:01:31.250Z",
  "__v": 0
}
```



### Validating a token
Token validation can be done by sending a `POST` request to `/users/me` with a JSON body that includes a `token` key and the token you wish to check as the value:

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7ImlkIjoiNjMxNGMxNDY5ODllYzNmMzlhOGFkNjY2In0sImlhdCI6MTY2MjMwNDU4MiwiZXhwIjoxNjY0ODk2NTgyfQ.rWmExtNh4Z1WA37Tni-kJ-ThE4zff2jYNpGOxJHjgWw"
}
```

A response will be sent for valid requests that will include the token that was validated, the associated user and a `sessionEnd` key that contains the expiration date of the token:

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7ImlkIjoiNjMxNGMxNDY5ODllYzNmMzlhOGFkNjY2In0sImlhdCI6MTY2MjMwNDU4MiwiZXhwIjoxNjY0ODk2NTgyfQ.rWmExtNh4Z1WA37Tni-kJ-ThE4zff2jYNpGOxJHjgWw",
  "user": "username@servicedomain.ext",
  "sessionEnd": 1662307291
}

```



### Logging a user in
Users can log in by sending a `POST` request to `/auth` with a JSON body that includes an `email` and `password` key:

```json
{
  "email": "username@servicedomain.ext",
  "password": "Secure User P@ssword123",
}
```

A response will be sent for valid requests that will include a new JWT token, the user and when their session ends:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7ImlkIjoiNjMxNGMxNDY5ODllYzNmMzlhOGFkNjY2In0sImlhdCI6MTY2MjMwNDU4MiwiZXhwIjoxNjY0ODk2NTgyfQ.rWmExtNh4Z1WA37Tni-kJ-ThE4zff2jYNpGOxJHjgWw",
  "user": "username@servicedomain.ext",
  "sessionEnd": 1662309732
}
```



### Updating a user
Updates can be made for a specific user in the database by sending a `PUT` request to `/users`.

> This is a private route that will require a valid token in the request header: `x-auth-token: ${token}`.

```json
{
	"email": "updatedEmail@servicedomain.ext",
	"password": "Changed P@ssword123",
	"confirmPassword": "Changed P@ssword123",
	"trustedDevice": true
}
```

In the example above, the user has changed both their `email` address and `password`.

A response will be sent for valid requests that will include the token for that user, the user, when their session ends and a message confirming the account update — for further use on the front-end.

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7ImlkIjoiNjMxNGMxNDY5ODllYzNmMzlhOGFkNjY2In0sImlhdCI6MTY2MjMwNDU4MiwiZXhwIjoxNjY0ODk2NTgyfQ.rWmExtNh4Z1WA37Tni-kJ-ThE4zff2jYNpGOxJHjgWw",
  "user": "updatedEmail@servicedomain.ext",
  "sessionEnd": 1664898494,
  "message": "Account updated."
}
```



### Deleting a user
Deleting a user can be done by sending a `DELETE` request to `/users` with a JSON body that includes a `confirmation` key with `DELETE` as it's value.

> This is a private route that will require a valid token in the request header: `x-auth-token: ${token}`.

```json
{
  "confirmation": "DELETE"
}
```

A response will be sent for valid requests that will include a message confirming the user has been removed from the database — for further use on the front-end.

```json
{
  "message": "Account deleted."
}
```



### Resetting a user password
The process of having a user reset their password is already set up for you.  This includes temporary request token generation and reset link email sending.

Password reset requests are done in `ResetPassword.js` by initially sending a `POST` to `/emails/pw-reset` with a JSON body that includes an `email` key with the user email as it's value.

```json
{
  "email": "username@servicedomain.ext"
}
```

**Note**: For security reasons, a generic message will be returned stating the refresh token required for password resetting is unable to be created if any issue is encountered, for any reason, in the request:

```json
{
  "errors": [
    {
      "message": "Unable to create reset token."
    }
  ]
}
```

If the request is valid, an email is dispatched with a, one-time and temporary, reset link that includes a request token.  A response will also be sent:

```json
{
  "message": "Request received. Check email to proceed."
}
```

Once the user has checked their email and clicks the reset link, they should be taken to a new form, `SetPassword.js`, to enter their new password.
If their request token is valid, an update request will be kicked off automatically to update the user in the database — see "Updating a user" above, for specifics.  If the request token is no longer valid at the time of submission, the request token will be cleared and the user will be informed that the token is no longer valid and to try the process again.

If the final password change request is valid, the user's password will be updated successfully — including the "Account updated." notification message.


## Email Sending
SendGrid is the service being used to dispatch emails.  You can find the `/email` route and controller in *routes/emailRoutes* and *controllers/emailController.js*.
The incoming payload from the front-end is validated with express-validator, shown here:
```javascript
const checkEmailPayload = [
  check('email')
    .notEmpty().withMessage('Email is required.')
    .isEmail().withMessage('Invalid email.'),
];
```

> Be sure to provide a valid SendGrid API key for *REACT_APP_SENDGRID_KEY* in *.env*.
> Your **from** key will be the value of *REACT_APP_VERIFIED_SENDER_EMAIL* in *.env*.
> Please make sure your SendGrid send address is verified in the SendGrid dashboard or a 403: Forbidden will be returned.

The main composition and sending continues in the *sendEmail* function.
Here is a cut down version in *controllers/emailController.js* &mdash; see file for full implementation:
```javascript
try {
  if (!apiKey) {
    return res.status(400).json({
      error: 'Email service key not provided.'
    });
  }

  const msg = {
    to: email,
    from: sendAddress,
    subject: "Test email dispatched.",
    text: 'A test email has successfully been dispatched from the Starter App project.',
    html:
      `<strong>
        A test email has successfully been dispatched from the Starter App project.
      </strong>`,
  };

  // await sgMail.send(msg);

  res.json({ result: "Email successfully sent." });
} catch(error) {
  res.status(500).json({ error });
}
```

The `await sgMail.send(msg);` call has been disabled for the live app example.  Be sure to uncomment it when you want actual delivery of the email,
or see SendGrid's documentation for configuring a sandbox environment if that suits your needs.