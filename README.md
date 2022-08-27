# streetweary

Deployed At: [https://streetweary.netlify.app/](https://streetweary.netlify.app/)

### Created By Isak Kallenbach

#### Technologies Used: Javascript, PostgreSQL, Express, React, Node.js, HTML5, CSS3 

This is a mock clothing store app focused specifically around streetwear fashion. The site allows you to browse, add items to a cart, create an account, login, checkout, etc.

I wanted to make an online shopping site, because online shopping is such a massive part of our lives and I wanted to try my hand at it. So when the question for what the site would "sell" popped into my head, the first answer was clothing, as I'm into fashion and most of the online shopping I do is on clothing websites (though most of it is the online equivalent of window shopping).


## Instructions

The following instructions are for local use only. Instructions that are necessary only for deployment will be marked accordingly.

#### Database

Create and connect to a database. I use Postbird for local databases, but anything, including the CLI, work perfectly fine. 

Copy and paste the contents of the **clothing-store.sql** file in the server/db directory to create all the necessary tables.

Use the **products.sql** file in the same directory to insert some items into the tables.

#### Server

These instructions are meant to be done solely in the server diretory:

Create an .env file with these environment variables (values can be with or without quotes):

- **DB_USER=** Your database username.
- **DB_PASSWORD=** Your database password.
- **DB_PORT=** The port that your database is connected to (This is normally 5432).
- **DB_DATABASE=** Your database's name.
- **DB_HOST=** The host address. **Deployment Only** - I'm pretty sure.
- **PORT=** The Port you want to open the server on (I had 5000, just pick something that isn't 3000, which is where the Client opens). This port needs to be reflected in the Client .env variables.
- **GOOGLE_CLIENT_ID=** For OAuth2. Get from Google.
- **GOOGLE_CLIENT_SECRET=** For OAuth2. Get from Google.
- **GOOGLE_CALLBACK_URL=** OAuth Google Redirect for Server. **Deployment Only**
- **GOOGLE_FRONT_END_REDIRECT_URL=** OAuth Google Redirect for Client. **Deployment Only**
- **JWT_KEY=** Can be any random string. Used to verify JWT.
- **STRIPE_KEY=** For Stripe card payments. Get from Stripe.
- **CORS_ORIGIN=** The URL where you deployed your front-end. **Deployment Only**

The following commands are meant to be typed into the terminal at the server's directory:

##### 1. npm install

This will install all modules and dependencies needed to run the app.

##### 2. npm start

This should set the app listening at [http://localhost:5000](http://localhost:5000). Or whatever you've set your PORT variable to.

#### Client

These instructions are meant to be done solely in the client diretory:

Create an .env file with these environment variables (values can be with or without quotes):

- **REACT_APP_SERVER_URL=**http://localhost:5000/api
- **REACT_APP_DEV_URL=**http://localhost:5000
- **REACT_APP_GOOGLE_URL=**http://locahost:5000/api/auth/google

I have localhost:5000, but remember this should be whatever the PORT= env variable is in the server directory.

The following commands are meant to be typed into the terminal at the server's directory:

##### 1. npm install

This will install all modules and dependencies needed to run the app.

##### 2. npm start

This should open your app at [http://localhost:3000](http://localhost:3000).

<br>
#### My Links:
[Personal Portfolio](https://kallenbach13.github.io/personal-portfolio-website/)
<br>
[Github](https://github.com/kallenbach13)