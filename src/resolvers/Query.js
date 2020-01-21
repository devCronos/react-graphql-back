const {forwardTo} = require ('prisma-binding');
const {hasPermission} = require('../utils');

const Query = {
    items: forwardTo('db'),
    item: forwardTo('db'),
    itemsConnection: forwardTo('db'),
    me(parent,args,ctx,info) {
        // check if there is a current user ID
        if(!ctx.request.userId) return null;
        // its ok to return a promise
        return ctx.db.query.user({
            where: {id: ctx.request.userId}
        }, info)
    },
    async users(parent,args,ctx,info){
        //check if logged in
        if(!ctx.request.userId) throw new Error('You must be logged in!');
        // check if the user has the permissions to query the permissions
        hasPermission(ctx.request.user, ['ADMIN','PERMISSIONUPDATE']);
        // if they do, querry all the users
        return ctx.db.query.users({}, info);
    },
    async order(parent, args,ctx,info){
        // check login status
        if(!ctx.request.userId) throw new Error('You are not logged in!');
        // querry the order
        const order = await ctx.db.query.order({
            where: {id: args.id}
        }, info)
        // check for permission
        const ownsOrder = order.user.id === ctx.request.userId;
        const hasPermissionToSeeOrder = ctx.request.user.permissions.includes('ADMIN');
        if(!ownsOrder || !hasPermissionToSeeOrder) throw new Error('You can\'t do that');
        // return the order
        return order;
    },
    async orders(parent, args, ctx,info){
        const {userId} = ctx.request;
        if(!userId) throw new Error ('You must be logged in!');
        return ctx.db.query.orders({
            where: {
                user: {id: userId}
            }
        }, info)
    }
};

module.exports = Query;
