var app = require('express')(),
    session = require('express-session'),
    cookie = require('cookie'),
    bparser = require('body-parser'),
    cookieParser = require('cookie-parser'),
    sessionStore = new session.MemoryStore(),
    socketStore = {};
    hostedRooms = {};


var COOKIE_SECRET = 'secret';
var COOKIE_NAME = 'sid';

app.set('view engine', 'ejs');
app.use(bparser.json());
app.use(bparser.urlencoded({extended:true}));
app.use(cookieParser(COOKIE_SECRET));
app.use(session({
    name: COOKIE_NAME,
    store: sessionStore,
    secret: COOKIE_SECRET,
    saveUninitialized: true,
    resave: true,
    cookie: {
        path: '/',
        httpOnly: true,
        secure: false,
        maxAge: null
    }
}));

app.get('/watch/:host', function (req, res, next) {
    res.render('redir', { room: req.params.host });
});

app.get('/watcher/check', function (req, res, next) {
    res.send([io.sockets.adapter.rooms['testroom'], hostedRooms]);
});

app.get('/watch', function (req, res, next) {
    var room, sid, cookies;

    room = req.query.room;
    cookies = cookie.parse(req.headers.cookie);
    sid = cookieParser.signedCookie(cookies[COOKIE_NAME], COOKIE_SECRET);

    socketStore[sid].join('testroom');
    hostedRooms[room].sockets.push(sid);
    res.render('watch', { video: hostedRooms[room].video, listener : true, sessionHost: room });
});

app.get('/host', function (req, res, next) {
    res.render('host');
});

app.post('/host', function (req, res, next) {
    var data = {},
        start = function() {
            var video, tokens, token;

            video = req.body.video;
            tokens = video.split('?')[1].split('&');
            for(var i = 0; i < tokens.length; i++) {
                token = tokens[i].split('=');
                if(token[0] === 'v') {
                    return host_video(null, token[1])
                }
            }

            return res.send('no video');
        },
        host_video = function (err, result) {
            if(err) {
                console.log('error on video', err);
                return next(err);
            }

            var cookies, sid;

            cookies = cookie.parse(req.headers.cookie);
            sid = cookieParser.signedCookie(cookies[COOKIE_NAME], COOKIE_SECRET);
            console.log('hosted on session ', sid);

            hostedRooms[sid+'-'+result] = { video: result, sockets : [] }

            send_response(err, { video: result, host: sid+'-'+result });
        },
        send_response = function (err, result) {
            if(err) {
                return next(err);
            }

            res.render('watch', { 
                video: result.video,
                listener: false,
                sessionHost: result.host,
                shareLink: 'http://'+req.headers.host+'/watch/'+result.host
            });
        };
    start();
});

var server = require('http').Server(app).listen(3000),
    io = require('socket.io')(server);

io.use(function(socket, next) {
    try {
        var data = socket.handshake || socket.request;
        if (! data.headers.cookie) {
            return next(new Error('Missing cookie headers'));
        }
        console.log('cookie header ( %s )', JSON.stringify(data.headers.cookie));
        var cookies = cookie.parse(data.headers.cookie);
        console.log('cookies parsed ( %s )', JSON.stringify(cookies));
        if (! cookies[COOKIE_NAME]) {
            return next(new Error('Missing cookie ' + COOKIE_NAME));
        }
        var sid = cookieParser.signedCookie(cookies[COOKIE_NAME], COOKIE_SECRET);
        if (! sid) {
            return next(new Error('Cookie signature is not valid'));
        }
        console.log('session ID ( %s )', sid);
        data.sid = sid;
        socket.session_id = sid;
        socketStore[sid] = socket;
        sessionStore.get(sid, function(err, session) {
            if (err) return next(err);
            if (! session) return next(new Error('session not found'));
            data.session = session;
            next();
        });
    } catch (err) {
        console.error(err.stack);
        next(new Error('Internal server error'));
    }
});

io.on('connection', function(socket) {
    socket.on('join', function(data) {
        socket.join(data);
    });
    socket.on('play', function(data) {
        console.log('will play', data, ' from ', socket.session_id)
        io.sockets.in(data.room).emit('play', data.time);
    });

    socket.on('pause', function(data) {
        console.log('will pause ', socket.session_id);
        io.sockets.in(data.room).emit('pause', data.time)
    });

    socket.on('play-seek', function(data) {
        console.log('playseek ', socket.session_id, data);
        io.sockets.in(data.room).emit('play-seek', [data.time, data.state]);
    });

    socket.on('get-current', function(data) {
        var request = socket.session_id;

    });
}); 