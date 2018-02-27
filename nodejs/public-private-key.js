const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');

const dataToSign = {
  sub: '1234567890',
  name: 'John Doe',
  admin: true
};
const privateKey = fs.readFileSync(
  path.join(__dirname, '..', 'keys', 'private-key-encrypted.pem')
);
const token = jwt.sign(
  dataToSign,
  {
    key: privateKey,
    passphrase: 'passphrase'
  },
  {
    algorithm: 'RS256',
    keyid: 'key-id-1' // Case sensitive key id
  }
);

console.log(token);
