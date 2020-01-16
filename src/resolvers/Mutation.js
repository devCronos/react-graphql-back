const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const {randomBytes} = require('crypto');
const {promisify} = require('util');
const {transport, makeANiceEmail} = require('../mail');
const {hasPermission} = require('../utils');


const mutations = {
    async createItem(parent, args, ctx, info) {
        // check if they are logged in
        if(!ctx.request.userId) throw new Error('You must be logged in to create an item');

        const item = await ctx.db.mutation.createItem({
            data: {
                user: {
                    // This  is how to create a relationship betwen the item and the user
                    connect: {
                        id: ctx.request.userId
                    }
                },
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
        const item = await ctx.db.query.item({where}, `{id title user{id} }`);
        // check for permission
        const ownsItem = item.user.id === ctx.request.userId;
        const hasPermissions = ctx.request.user.permissions.some(permission=>['ADMIN','ITEMDELETE'].includes(permission));
        if(!ownsItem && !hasPermissions) throw new Error("You don't have permissions");
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
            throw new Error(`No user found for email ${email}`);
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
    },
    async requestReset(parent, args, ctx, info){
        // check if user is real
        
        const user = await ctx.db.query.user({where: {email: args.email}});
        if(!user) throw new Error(`Noy user found for email ${email}`);
        // set a reset token and expiry
        
        const randomBytesPromisified = promisify(randomBytes);
        const resetToken = (await randomBytesPromisified(20)).toString('hex');
        const resetTokenExpiry = Date.now() + 3600000; // 1h
        const res = await ctx.db.mutation.updateUser({
            where: {email: args.email},
            data: {resetToken, resetTokenExpiry}
        });
        // email the reset token
        const mailRes = await transport.sendMail({
            from: 'cl@b.com',
            to: user.email,
            subject: 'Your password reset token',
            html: makeANiceEmail(`Your password reset token is here \n\n 
            <a href="${process.env.FRONTEND_URL}/reset?resetToken=${resetToken}"> Click here to reset </a>`)
        })

        return {message: 'Thanks!'};
    },
    async resetPassword(parent,args,ctx,info){
        // check password
        if(args.password !== args.confirmPassword) throw new Error("Your passwords don't match");
        // check the token
        // check expiry
        const [user] = await ctx.db.query.users({
            where: {
                resetToken: args.resetToken,
                resetTokenExpiry_gte: Date.now() - 3600000,
            }
        });
        if(!user) throw new Error('This token is either invalid or expired')
        // hash their new password
        const password = await bcrypt.hash(args.password, 10);
        // save the new password and remove the reset fields
        const updatedUser = await ctx.db.mutation.updateUser({
            where: {email: user.email},
            data: {
                password,
                resetToken: null,
                resetTokenExpiry: null
            }
        })
        // generate JWT
        const token = jwt.sign({userId: updatedUser.id},process.env.APP_SECRET);
        // set JWT cookie
        ctx.response.cookie('token', token, {
            httpOnly: true,
            maxAge: 1000*60*60*24*365
        });
        return updatedUser;
        // return new user
    },
    async updatePermissions (parent, args, ctx, info){
        // check logged in
        if(!ctx.request.userId) throw new Error('You must be logged in!');
        // query the current user
        const currentUser = await ctx.db.query.user({
            where: {
                id: ctx.request.userId
            }
        }, info)
        // check for permission to change permissions
        hasPermission(currentUser, ['ADMIN','PERMISSIONUPDATE']);
        // update permissions
        return ctx.db.mutation.updateUser({
            data: {
                permissions: {
                    set: args.permissions
                }
            },
            where: {
                id: args.userId
            }
        },info);
    }
};

module.exports = mutations;
