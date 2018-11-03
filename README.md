# ecdh
This is a example of EC-DH, which do DH base on Ecdsa and AES gcm mode to encrypt / decrypt message.



There are tow examples in dir [example](https://github.com/czminami/ecdh/blob/master/example/ecdh_example.go), please check for detail.

The first example Simplex, just similar to HTTPS between browser and server;

And the second example Duplex, which enhance the confidentiality, will use temporary tx-key to exchange message between peers. 