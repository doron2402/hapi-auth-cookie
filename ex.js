var Hapi = require('hapi');
var moment = require('moment');
var crypto = require("crypto");
var redis = require("redis");
var redis_client = redis.createClient();
var util = require('util');

redis_client.on("error", function (err) {
    console.log("Error " + err);
});

var cookie_name = 'site_cookie';

var users = {
    john: {
        id: 'john',
        password: 'password',
        name: 'John Doe'
    },
    doron: {
        id: 'doron',
        password: 'doron',
        name: 'Doron Segal'
    },
    admin: {
        id: 'admin',
        password: 'admin',
        name: 'Administrator',
        lastLoggedIn: null
    }
};
var validateAuth = function(request, reply, cb) {
    if (!request.auth.isAuthenticated) {
        return reply.redirect('/');
    }
     var user_tmp = String(request.auth.credentials.id);
     var UniqUserId = crypto.createHash("md5").update(user_tmp).digest("hex");
     redis_client.get(UniqUserId, function(err, result) {
        if (err || !result) {
            return reply.redirect('/');
        }
        //validate result for UA and auth_key
        var res = JSON.parse(result);
        if (res.ua != request.headers['user-agent'] || res.key != request.state.site_cookie.auth_key) {
            return reply.redirect('/');
        }
        return cb(err,result);
    });
};

var handlers = {};
handlers.profile = function(request, reply) {
    validateAuth(request, reply, function(err, result) {
       return reply('<html><head><title>Profile | '
        + request.auth.credentials.name
        + '</title></head><body><h3>Welcome '
        + request.auth.credentials.name
        + '</h3><br/></body></html>');
    });
};

handlers.home = function (request, reply) {
    console.log('hpme....');
    reply('<html><head><title>Login page</title></head><body><h3>Welcome '
      + request.auth.credentials.name
      + ' : ' + moment.unix(request.auth.credentials.lastLoggedIn).format("MM/DD/YYYY")
      + '!</h3><br/><form method="get" action="/logout">'
      + '<input type="submit" value="Logout">'
      + '</form></body></html>');
};

var login = function (request, reply) {

    if (request.auth.isAuthenticated) {
        return reply.redirect('/');
    }

    var message = '';
    var account = null;

    if (request.method === 'post') {

        if (!request.payload.username ||
            !request.payload.password) {

            message = 'Missing username or password';
        }
        else {
            if (users[request.payload.username]) {
                users[request.payload.username].lastLoggedIn = moment().utc().unix();
            }

            account = users[request.payload.username];
            if (!account ||
                account.password !== request.payload.password) {

                message = 'Invalid username or password';
            }
        }
    }

    if (request.method === 'get' ||
        message) {

        return reply('<html><head><title>Login page</title></head><body>'
            + (message ? '<h3>' + message + '</h3><br/>' : '')
            + '<form method="post" action="/login">'
            + 'Username: <input type="text" name="username"><br>'
            + 'Password: <input type="password" name="password"><br/>'
            + '<input type="submit" value="Login"></form></body></html>');
    }

    var tmp_key = String(moment().utc().unix());

    var UniqKey = crypto.createHash("md5").update(tmp_key).digest("hex");
    var tmp_username = String(request.payload.username);
    var UniqUserId = crypto.createHash("md5").update(tmp_username).digest("hex");
    var tmp_json = JSON.stringify({key: UniqKey, ua: request.headers['user-agent']});
    redis_client.set(UniqUserId, tmp_json, function(err, res) {

        request.server.app.cache.set(UniqUserId, { account: account, auth_key: UniqKey }, 0, function (err) {
            if (err) {
                reply(err);
            }

            request.auth.session.set({ sid: UniqUserId, auth_key: UniqKey});
            return reply.redirect('/');
        });
    }); //set value in redis
};

handlers.logout = function (request, reply) {

    request.auth.session.clear();
    return reply.redirect('/');
};

var server = new Hapi.Server(8000);

server.pack.register(require('./index.js'), function (err) {

    var cache = server.cache('sessions', { expiresIn: 3 * 24 * 60 * 60 * 1000 });
    server.app.cache = cache;

    server.auth.strategy('session', 'cookie', true, {
        password: 'secret',
        cookie: cookie_name,
        redirectTo: '/login',
        isSecure: false,
        validateFunc: function (session, callback) {

            cache.get(session.sid, function (err, cached) {

                if (err) {
                    return callback(err, false);
                }

                if (!cached) {
                    return callback(null, false);
                }

                //Validate Authentication Key
                if (!cached.item.auth_key || cached.item.auth_key != session.auth_key){
                    return callback('Wrong Auth Key', false);
                }

                console.log(cached);
                console.log(session);
                return callback(null, true, cached.item.account)
            })
        }
    });

    server.route([
        {   method: 'GET', path: '/',
            config: { handler: handlers.home }
        },{
            method: ['GET', 'POST'],
            path: '/login',
            config: {
                handler: login,
                auth: { mode: 'try' },
                plugins: {
                    'hapi-auth-cookie': {
                        redirectTo: false
                    }
                }
            }
        },{
            method: 'GET',
            path: '/logout',
            config: {
                handler:  handlers.logout
            }
        },{
            method: 'GET',
            path: '/profile',
            config: {
                handler: handlers.profile
            }
        }
    ]);

    server.start(function () {
        console.log('Server ready' + server.info.uri);
    });
});
