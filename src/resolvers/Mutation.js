const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const mutations = {
    async createItem(parent, args, ctx, info) {
        // TODO check if they are logged in

        const item = await ctx.db.mutation.createItem({
            data: {
                ...args
            }
        }, info);
        return item;
    },
    updateItem(parent, args, ctx, info) {
        // first take a copy of the updates
        const updates = {...args};
        // remove the ID from the updates
        delete updates.id;
        // run the update method
        return ctx.db.mutation.updateItem({
            data: updates,
            where: {
                id: args.id
            }
        },info)
    },
    async deleteItem(parent, args, ctx, info) {
        const where = {id: args.id};
        // find item
        const item = await ctx.db.query.item({where}, `{id title}`);
        // check for permission
        // delete
        return ctx.db.mutation.deleteItem({where}, info)
    },
    async signup(parent, args, ctx, info) {
        args.email = args.email.toLowerCase();
        // hash password 1way. bcrypt is async. salt makes it unique
        const password = await bcrypt.hash(args.password, 10);
        // create the user in the db
        const user = await ctx.db.mutation.createUser({
            data: {
                ...args,
                password,
                permissions: { set: ['USER'] }
            }
        },info)
        // create the JWT token
        const token = jwt.sign({ userId: user.id }, process.env.APP_SECRET);
        // set the JWT as a cookie on the response
        ctx.response.cookie('token', token, {
            httpOnly: true,
            maxAge: 1000*60*60*24*365
        });
        // return the user
        return user;
    },
    async signin(parent,{email, password},ctx,info){
        // check if user exists
        const user = await ctx.db.query.user({where: {email}});
        if(!user){
            throw new Error(`Noy user found for email ${email}`);
        }
        // check password
        const valid = await bcrypt.compare(password, user.password);
        if(!valid){
            throw new Error('Invalid password');
        }
        // generate the JWT token
        const token = jwt.sign({ userId: user.id }, process.env.APP_SECRET);
        // set the cookie with the token
        ctx.response.cookie('token', token, {
            httpOnly: true,
            maxAge: 1000*60*60*24*365
        });
        // return the user
        return user;
    },
    signout(parent, args, ctx, info){
        ctx.response.clearCookie('token');
        return {message: 'Goodbye!'};
    }
};

module.exports = mutations;
