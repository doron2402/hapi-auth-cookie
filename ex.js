var Hapi = require('hapi');
var moment = require('moment');
var crypto = require("crypto");
var redis = require("redis");
var redis_client = redis.createClient();

redis_client.on("error", function (err) {
    console.log("Error " + err);
});



var cookie_name = 'site_cookie';

var uuid = 1;       // Use seq instead of proper unique identifiers for demo only

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

var handlers = {};
handlers.profile = function(request, reply) {
    if (!request.auth.isAuthenticated) {
        return reply.redirect('/');
    }
   
   
    redis_client.get(request.auth.credentials.id, function(err, result){
	console.log('getting from redis using id: ' + request.auth.credentials.id);
	if (err) { console.log(err); }
	console.log(result);
	return reply('<html><head><title>Profile | '
      	+ request.auth.credentials.name
      	+ '</title></head><body><h3>Welcome '
      	+ request.auth.credentials.name
      	+ '</h3><br/></body></html>');
    });
};

handlers.home = function (request, reply) {

    reply('<html><head><title>Login page</title></head><body><h3>Welcome '
      + request.auth.credentials.name
      + ' : ' + moment.unix(request.auth.credentials.lastLoggedIn).format("MM/DD/YYYY")
      + '!</h3><br/><form method="get" action="/logout">'
      + '<input type="submit" value="Logout">'
      + '</form></body></html>');
};

var login = function (request, reply) {

    if (request.auth.isAuthenticated) {

        redis_client.get(request.auth.credentials.id, function(err, ret) {
            console.log('err');
            console.log(err);
            console.log('ret');
            console.log(ret);
	    return reply.redirect('/');
        });
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

    var sid = String(++uuid);
    var tmp_key = String(moment().utc().unix());

    var UniqKey = crypto.createHash("md5").update(tmp_key).digest("hex");
    redis_client.set(account.id, UniqKey); //set value in redis
    request.server.app.cache.set(sid, { account: account, auth_key: UniqKey }, 0, function (err) {

        if (err) {
            reply(err);
        }

        request.auth.session.set({ sid: sid, auth_key: UniqKey});
        return reply.redirect('/');
    });
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
