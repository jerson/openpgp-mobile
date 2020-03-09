const express = require('express');
const cors = require('cors');
express.static.mime.define({'application/wasm': ['wasm']});
var app = express();

app.use(cors());
app.use('/', express.static('public'));

app.listen(3000, function () {
    console.log('Wasm app listening on port 3000!')
});