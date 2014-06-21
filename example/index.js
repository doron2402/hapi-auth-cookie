var Hapi = require('hapi');
var moment = require('moment');
var crypto = require("crypto");
var sha256 = crypto.createHash("sha256");


var uuid = 1;       // Use seq instead of proper unique identifiers for demo only

var users = {
    john: {
        id: 'john',
        password: 'password',
        name: 'John Doe',
        lastLoggedIn: null
    },
    admin: {
        id: 'admin',
        password: 'admin',
        name: 'Administrator',
        lastLoggedIn: null
    }
};

var home = function (request, reply) {

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
            console.log(account);
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
    var tmp_key = 'date: ' + moment().utc().unix();
    sha256.update(String(tmp_key), "utf8");
    var UniqKey = sha256.digest("base64");

    request.server.app.cache.set(sid, { account: account }, 0, function (err) {

        if (err) {
            reply(err);
        }

        request.auth.session.set({ sid: sid , MyKey: UniqKey});
        return reply.redirect('/');
    });
};

var logout = function (request, reply) {

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
        { method: 'GET', path: '/', config: { handler: home } },
        { method: ['GET', 'POST'], path: '/login', config: { handler: login, auth: { mode: 'try' }, plugins: { 'hapi-auth-cookie': { redirectTo: false } } } },
        { method: 'GET', path: '/logout', config: { handler: logout } }
    ]);

    server.start(function () {

        console.log('Server ready' + server.info.uri);
    });
});
