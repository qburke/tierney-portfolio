const express = require('express');
const bkfd2Password = require("pbkdf2-password");
const fs = require('fs');
const multer  = require('multer')
const UIDGenerator = require('uid-generator');
const { config, send } = require('process');
const archiver = require('archiver');

const app = express();
const hasher = bkfd2Password();
const uidgen = new UIDGenerator();

var storage = multer.diskStorage({
    destination: './public',
    filename: function (req, file, cb) {
        let fields = file.fieldname.split('-');
        if(fields.length != 2 ) {
            console.log('Malformed fieldname: ' + file.fieldname);
            return cb(null, 'tmp/'+file.fieldname);
        }
        var parent1 = '';
        var parent2 = '';
        switch(fields[0]) {
            case 'tmp':
                parent1 = 'tmp';
                break;
            case 'main':
                parent1 = 'images';
                break;
            default:
                parent1 = 'tmp'
        }
        switch(fields[1]) {
            case 'full':
                parent2 = 'fulls';
                break;
            case 'thumb':
                parent2 = 'thumbs';
                break
            default:
                parent2 = '';
        }
        // handle spaces
        cb(null, parent1 + '/' + parent2 + '/' + file.originalname);
    }
})  
var upload = multer({ storage: storage })
const MAX_UPLOAD = 524288000; // 500 MB

const authPath = "./auth.json";
let passHash = "";
let passSalt = "";
let tokens = {};
const TOKEN_TIMEOUT = 36000000;

function isValidToken (token) {
    return token in tokens && Date.now() - tokens[token] < TOKEN_TIMEOUT;
}

function authenticate (req, res, next) {
    if (isValidToken(req.query.token))
        next();
    else
        res.sendStatus(403);
}

try {
    ['./public/images/fulls', './public/images/thumbs', './public/tmp/fulls', './public/tmp/thumbs']
    .forEach(folder => {
        if (!fs.existsSync(folder))
            fs.mkdirSync(folder, { recursive: true });
    });
} catch (err) {
    console.error(err);
}

if (fs.existsSync(authPath)) {
   let auth = JSON.parse(fs.readFileSync(authPath));
    passHash = auth.hash;
    passSalt = auth.salt;
    if(passHash === "" || passSalt === "")
        throw Error("No editor password set.");
} else {
    const password = process.env.PASSWORD;
    let opts = {
        password: password
    };
    hasher(opts, function(err, pass, salt, hash) {
        let authData = {
            hash: hash,
            salt: salt
        };
        fs.writeFileSync(authPath, JSON.stringify(authData));
        passHash = hash;
        if(passHash === "")
            throw Error("No editor password set.");    
    });
}

app.use(express.static('public'));
app.use(express.json());

app.get('/', function (req, res) {
    fs.access('./index.html', fs.constants.F_OK, (err) => {
        if (err) {
            res.sendFile('index.html', { root: './public/assets/templates' });
        } else {
            res.sendFile('index.html', { root: __dirname });
        }
      });
});

app.get('/login', function (req, res) {
    res.sendFile('login.html', { root: __dirname });
});

app.post('/login', function (req, res) {
    opts = {
        password: req.body.password,
        salt: passSalt
    };
    hasher(opts, function(err, pass, salt, hash) {
        if(hash === passHash) {
            uidgen.generate().then(uid => {
                tokens[uid] = Date.now();
                res.send(uid);
            });
        } else {
            res.sendStatus(401);
        }
    });
});

app.get('/edit', authenticate, function(req, res) {
    fs.access('./edit.html', fs.constants.F_OK, (err) => {
        if (err) {
            fs.access('./site-config.json', fs.constants.F_OK, (err) => {
                if (err) {
                    res.sendFile('edit.html', { root: './public/assets/templates' });
                } else {
                    // generate from site-config.json
                }
              });
        } else {
            res.sendFile('edit.html', { root: __dirname });
        }
      });
});

app.get('/download-img', authenticate, function(req, res) {
    const archive = archiver('zip', { zlib: { level: 9 } });
    res.attachment('index_images.zip');
    archive.pipe(res);

    archive.on('warning', function(err) {
        if (err.code === 'ENOENT') {
          // log warning
        } else
          throw err;
    });
    archive.on('error', function(err) {
        throw err;
    });
    
    archive.directory('./public/images/fulls', 'fulls');
    archive.directory('./public/images/thumbs', 'thumbs');
    archive.finalize();
});

app.get('/download-conf', authenticate, function(req, res) {
    res.sendFile('site-config.json', { root: __dirname });
});

function emptyDir (directory, callback) {

    fs.readdir(directory, (err, files) => {
        if (err) throw err;
      
        files.forEach(file => {
          fs.unlinkSync(directory + '/' + file);
        });
        
        callback();
    });
}

function verifyContentLength (req, res, next) {
    var uploadSize = req.get("Content-Length");
    if (uploadSize > MAX_UPLOAD) {
        console.log(`Max upload size exceeded (Total size: ${uploadSize} bytes)`);
        return res.status(413).send("Exceeded max upload size (500 MB).");
    } else {
        if (req.query.mode == 'tmp') {
            emptyDir('./public/tmp/thumbs', () => emptyDir('./public/tmp/fulls', next));
        } else if (req.query.mode == 'main') {
            emptyDir('./public/images/fulls', () => emptyDir('./public/images/thumbs', next));
        } else {
            return res.status(400).send("Edit mode not set.");
        }
        next();
    }
}

app.post('/upload-images',
    authenticate,
    verifyContentLength,
    upload.fields([
        { name: 'tmp-full', maxCount : 40 },
        { name: 'tmp-thumb', maxCount : 40 },
        { name: 'main-full', maxCount : 40 },
        { name: 'main-thumb', maxCount : 40 }
    ]), 
    function(req, res) {
        res.send("Success");
});

app.post('/update', authenticate, function(req, res) {
    fs.writeFile('site-config.json', req.body, function (err) {
        if (err) throw err;
        fs.writeFile('index.html', generateHtml(req.body, 'images'), function (err) {
            if (err) throw err;
            res.send("Success");
        });
    });
});

app.post('/preview', authenticate, function(req, res) {
    fs.writeFile('preview.html', generateHtml(req.body, 'tmp'), function (err) {
        if (err) throw err;
        res.send("Success");
    });
});

app.get('/preview', authenticate, function(req, res) {
    res.sendFile('preview.html', { root: __dirname });
});

app.listen(process.env.PORT);

function generateHtml(meta, imgRoot) {
    var cards = '';
    meta["cards"].forEach(e => {
            cards += `<article class="thumb">
                <a href="${imgRoot}/fulls/${encodeURIComponent(e["imageName"])}" class="image"><img src="${imgRoot}/thumbs/${encodeURIComponent(e["thumbnailName"])}" alt="" /></a>
                <h2>${e["title"]}</h2>
                <p>${e["description"]}</p>
            </article>` + '\n'
        }
    );
    var socials = '';
    meta["socials"].forEach(e => {
        var link = e["link"];
        var name = e["name"];
        var upperName = e["name"].charAt(0).toUpperCase() + e["name"].slice(1);
        if(link != null) {
            socials += `<li><a href="${link}" class="icon brands fa-${name}"><span class="label">${upperName}}</span></a></li>` + '\n'
        }
    });
    return `<!DOCTYPE HTML>
    <html>
        <head>
            <title>${meta["siteTitle"]}</title>
            <meta charset="utf-8" />
            <meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=no" />
            <link rel="stylesheet" href="assets/css/main.css" />
            <noscript><link rel="stylesheet" href="assets/css/noscript.css" /></noscript>
        </head>
        <body class="is-preload">
    
            <!-- Wrapper -->
                <div id="wrapper">
    
                    <!-- Header -->
                        <header id="header">
                            <h1><a href="index.html"><strong>${meta["siteTitle"]}</strong></a></h1>
                            <nav>
                                <ul>
                                    <li><a href="#footer" class="icon solid fa-info-circle">About</a></li>
                                </ul>
                            </nav>
                        </header>
    
                    <!-- Main -->
                        <div id="main">
                            ${cards}
                        </div>
    
                    <!-- Footer -->
                        <footer id="footer" class="panel">
                            <div class="inner split">
                                <div>
                                    <section>
                                        <h2>${meta["aboutTitle"]}</h2>
                                        <p>${meta["aboutText"]}</p>
                                    </section>
                                    <section>
                                        <h2>Follow me on ...</h2>
                                        <ul class="icons">
                                            ${socials}
                                        </ul>
                                    </section>
                                    <p class="copyright">
                                        Design: <a href="http://html5up.net">HTML5 UP</a>.
                                    </p>
                                </div>
                            </div>
                        </footer>
    
                </div>
    
            <!-- Scripts -->
                <script src="assets/js/jquery.min.js"></script>
                <script src="assets/js/jquery.poptrox.min.js"></script>
                <script src="assets/js/browser.min.js"></script>
                <script src="assets/js/breakpoints.min.js"></script>
                <script src="assets/js/util.js"></script>
                <script src="assets/js/main.js"></script>
    
        </body>
    </html>`
}