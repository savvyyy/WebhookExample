const express = require('express');
const app = express();
const port = 3001;

app.get('/', function(req, res) {
    res.send('app.js is running!!');
    console.log('hellooooo')
})

app.listen(port , () => console.log(`Server is listening on the port ${port}`))