const pkceChallenge = require('pkce-challenge');
const cookie = require('cookie');

module.exports = (req, res) => {
  const challenge = pkceChallenge(128);

  // Store the verifier in a secure, HttpOnly cookie
  res.setHeader('Set-Cookie', cookie.serialize(
    'pkce_verifier', 
    challenge.code_verifier, 
    {
      httpOnly: true,
      secure: process.env.NODE_ENV !== 'development',
      maxAge: 60 * 15, // 15 minutes
      path: '/',
    }
  ));
  
  // Send the code challenge to the frontend
  res.status(200).json({
    code_challenge: challenge.code_challenge,
  });
};