// api/redirect.js
export default function handler(req, res) {
  const target = "http://localhost:5000/hackaicon_ethiack_1337_lmao";

  res.writeHead(302, { Location: target });
  res.end();
}
