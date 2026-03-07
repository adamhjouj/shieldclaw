require('dotenv').config();

const express = require('express');
const app = express();

app.use(express.json());

app.use('/backboards', require('./routes/backboards-webhook'));
app.use('/backboards', require('./routes/prompt-gateway'));

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`CIBA webhook service listening on port ${PORT}`);
});
