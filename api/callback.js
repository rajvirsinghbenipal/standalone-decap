const { AuthorizationCode } = require('simple-oauth2');
const cookie = require('cookie');

module.exports = async (req, res) => {
  const { code } = req.query;
  const cookies = cookie.parse(req.headers.cookie || '');
  const code_verifier = cookies.pkce_verifier;

  if (!code || !code_verifier) {
    return res.status(400).json({ error: 'Missing code or verifier.' });
  }

  const client = new AuthorizationCode({
    client: {
      id: process.env.OAUTH_CLIENT_ID,
      secret: process.env.OAUTH_CLIENT_SECRET,
    },
    auth: {
      tokenHost: 'https://github.com',
      tokenPath: '/login/oauth/access_token',
    },
  });

  try {
    const accessToken = await client.getToken({
      code,
      redirect_uri: `https://punjabi-news-admin.vercel.app/callback`,
      code_verifier, // Send the proof key to GitHub
    });

    res.setHeader('Set-Cookie', cookie.serialize('pkce_verifier', '', {
      httpOnly: true,
      secure: process.env.NODE_ENV !== 'development',
      expires: new Date(0),
      path: '/',
    }));

    res.status(200).json({ token: accessToken.token.access_token });

  } catch (error) {
    console.error('PKCE Access Token Error:', error.message);
    res.status(500).json({ error: 'Authentication failed.' });
  }
};