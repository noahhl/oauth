GetRequestToken <- function(params, noisy=FALSE) {
  params$oauth_timestamp <- as.character(round(as.numeric(as.POSIXlt(Sys.time(), tz="UTC")),0))
  params$oauth_nonce <- paste(letters[runif(20, 1, 27)], sep="", collapse="")
   res       <- basicTextGatherer()
   uri       <- params$server$initiate
   request_params    <- c(params['oauth_callback'], params['oauth_consumer_key'], params['oauth_nonce'], params['oauth_signature_method'], params['oauth_timestamp'], params['oauth_version'])
   signature <- SignForOauth(uri, "POST", request_params, params$oauth_consumer_secret, "")
   request_params    <- c(request_params, oauth_signature=signature)
   curlPerform(url           = uri,
               verbose       = noisy,
               writefunction = res$update,
               customrequest="POST",
               httpheader    = c(Expect        = "",
                                 Authorization = GenerateOauthHeader(request_params)))
  res <- res$value()
  res <- strsplit(res, "&")[[1]]
  tokens <- c()
  for(i in 1:length(res)) {
    tokens[strsplit(res[i], "=")[[1]][1]] <- strsplit(res[i], "=")[[1]][2]
  }
  return(tokens)
}

GetAuthorization <- function(params) {
  url <- paste(params$server$auth, "?oauth_token=", params$oauth_token, sep="")
  cat("Go to: ", url)
  cat("\n\nEnter the oauth_verifier received there:")
  oauth_verifier <- readline()
}


GetAccessToken <- function(params, noisy=FALSE) {
  params$oauth_timestamp <- as.character(round(as.numeric(as.POSIXlt(Sys.time(), tz="UTC")),0))
  params$oauth_nonce <- paste(letters[runif(20, 1, 27)], sep="", collapse="")
   res    <- basicTextGatherer()
   uri    <- params$server$token    
   request_params <- c(params['oauth_consumer_key'], params['oauth_nonce'], params['oauth_signature_method'], params['oauth_timestamp'], params['oauth_token'], params['oauth_verifier'],params['oauth_version'])
   signature <- SignForOauth(uri, "POST", request_params, params$oauth_consumer_secret, params$oauth_token_secret)
   request_params    <- c(request_params, oauth_signature=signature)
   curlPerform(url           = uri,
               verbose       = noisy,
               writefunction = res$update,
               customrequest = "POST",
               httpheader    = c(Expect        = "",
                                 Authorization = GenerateOauthHeader(request_params, "auth")))
   res <- res$value()
   res <- strsplit(res, "&")[[1]]
   tokens <- c()
   for(i in 1:length(res)) {
     tokens[strsplit(res[i], "=")[[1]][1]] <- strsplit(res[i], "=")[[1]][2]
   }
   return(tokens)
}

