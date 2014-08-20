var Hapi = require('hapi');


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
    }
};

var handlers = {};
handlers.profile = function(request, reply) {
    if (!request.auth.isAuthenticated) {
        return reply.redirect('/');
    }

    return reply('<html><head><title>Profile | '
      + request.auth.credentials.name
      + '</title></head><body><h3>Welcome '
      + request.auth.credentials.name
      + '</h3><br/></body></html>');
};

handlers.home = function (request, reply) {

    reply('<html><head><title>Login page</title></head><body><h3>Welcome '
      + request.auth.credentials.name
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
    request.server.app.cache.set(sid, { account: account }, 0, function (err) {

        if (err) {
            reply(err);
        }

        request.auth.session.set({ sid: sid });
        return reply.redirect('/');
    });
};

handlers.logout = function (request, reply) {

    request.auth.session.clear();
    return reply.redirect('/');
};

var server = new Hapi.Server(8000);

server.pack.register(require('../'), function (err) {

    var cache = server.cache('sessions', { expiresIn: 3 * 24 * 60 * 60 * 1000 });
    server.app.cache = cache;

    server.auth.strategy('session', 'cookie', true, {
        password: 'secret',
        cookie: 'sid-example',
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

        console.log('Server ready');
    });
});
