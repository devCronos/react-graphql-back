# Advanced-React backend for shop app

* GraphQL

* Prisma

* GraphQL Yoga Server

* CRUD

* Data Relationship

* Sending email for password reset flow

* Deploying Prisma Server to Heroku
* Deploying Yoga Server to Heroku



datamodel.graphql = schema for prisma => changes must be deplyed to prisma and execute that post-deploy hook
<br>
=> it updates prisma.graphql makes the functions for the CRUD api that sits on top of graphQL
<br>
schema.graphql = public facing API. We are interfacing with it with javascript. 
<br>
               = where we define mutations, queries => GO TO MUTATIONS.JS/QUERY.JS to define the resolvers(+advanced logic)
<br>