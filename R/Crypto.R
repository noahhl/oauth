# crypto.R
# Cryptographic functions for oauth 1.0 implementations
# Currently supported: HMAC-SHA1
# To support: RSA-SHA1

HmacSha1 <- function(key ,msg) {
# Courtesty of https://gist.github.com/586468
  hashlength <- 20
  innerpad   <- rawToBits(as.raw(rep(0x36 ,64)))
  outerpad   <- rawToBits(as.raw(rep(0x5C ,64)))
  zero       <- rep(0 ,64)
  HexdigestToDigest <- function(digest) {
      as.raw(strtoi(substring(digest, (1:hashlength)*2-1, (1:hashlength)*2), 16))
  }
  if(length(strsplit(key, "")[[1]]) >= 64) {
      key.digested <- digest(key,serialize=FALSE,algo="sha1")
      key <- intToUtf8(strtoi(HexdigestToDigest(key.digested), 16))
  }
  key <- rawToBits(as.raw(append(utf8ToInt(key),zero)[1:64]))
  mac <- function(pad, text) {
      HexdigestToDigest(digest(append(packBits(xor(key,pad)), text),
                               serialize=FALSE,algo="sha1"))
  }
  mac(outerpad, mac(innerpad, charToRaw(msg)))
}
