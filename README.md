# koa-digest
Dead simple HTTP Digest Authentication For The KOA Framewok.

*Warning* - This implementation does not protect against replay attacks.


Like most fo the the other HTTP-Digest middleware floating around,
Koa-Digest was designed only for the purposes of temporarily locking down an 
app or endpoint against non determined attackers. The server nonce and client
nonce values are not checked for expiration or authenticity. Consequently an 
attacker could reuse captured request headers in a replay attack.