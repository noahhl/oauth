#Execute oauth test provided at http://term.ie/oauth/example/

library(oauth)
params <- list(oauth_consumer_key = "key", 
            oauth_consumer_secret = "secret", 
            oauth_callback="http://somedomain.com",
            oauth_signature_method = "HMAC-SHA1",
            oauth_version="1.0", 
            server = list(
                          #To get request token
                          initiate = "http://term.ie/oauth/example/request_token.php",
                          #For user authentication
                          auth = "http://term.ie/oauth/example",
                          #For access token
                          token = "http://term.ie/oauth/example/access_token.php"))
                                                    
params <- Authorize(params, save=F)

cat("Testing the term.ie/oauth/example example using HMAC_SHA1")
cat("Testing that oauth_token was received correctly: ", params$oauth_token == "accesskey", "\n")
cat("Testing that oauth_token_secret was received correctly: ", params$oauth_token_secret == "accesssecret", "\n")

testRequest <- MakeRequest(params, "http://term.ie/oauth/example/echo_api.php", "GET", c(method="foo", bar="baz"))
cat("Testing that a a request can be made correctly was received correctly: ", testRequest == "method=foo&bar=baz", "\n")
