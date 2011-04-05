library(RCurl)
library(digest)
#source("Signature.R")
#source("Authorizer.R")


Authorize <- function(params, noisy=F, save=T) {
  params$oauth_nonce = paste(letters[runif(20, 1, 27)], sep="", collapse="")
  params$oauth_timestamp = as.character(round(as.numeric(as.POSIXlt(Sys.time(), tz="UTC")),0))

  a <- GetRequestToken(params, noisy)
  for(i in 1:length(a)) {
    params[names(a[i])] <- a[i]
  }
  params$oauth_verifier <- GetAuthorization(params)

  a <- GetAccessToken(params, noisy)
  for(i in 1:length(a)) {
    params[names(a[i])] <- a[i]
  }

  if(save) {
    save(params, file=paste("~/.oauthparams_", params$oauth_consumer_key, ".Rdata", sep=""))
  }
  return(params)
}  

LoadCredentials <- function(consumer_key) {
  return(load(file=paste("~/.oauthparams_", consumer_key, ".Rdata", sep="")))
}

MakeRequest <- function(params, resource, method, request=NULL, noisy=FALSE) {
  params$oauth_timestamp <- as.character(round(as.numeric(as.POSIXlt(Sys.time(), tz="UTC")),0))
  params$oauth_nonce <- paste(letters[runif(20, 1, 27)], sep="", collapse="")
  uri <- resource
  res    <- basicTextGatherer()
  if(!is.null(request)){
      r <- ""
    for(i in 1:length(request)) {
      r <- paste(r, paste(names(request[i]), "=", utils::URLencode(request[i]), sep=""), sep="&")
    }
    r <- sub("&", "", r)
    uri <- paste(resource, "?",  r, sep="")
  }
  request_params <- c(params['oauth_consumer_key'], params['oauth_nonce'], params['oauth_signature_method'], params['oauth_timestamp'], params['oauth_token'], params['oauth_version'], request)
    signature <- SignForOauth(resource, method, request_params, params$oauth_consumer_secret, params$oauth_token_secret) 
  request_params    <- c(request_params, oauth_signature=signature)

  curlPerform(url           = uri,
              verbose       = noisy,
              writefunction = res$update,
              customrequest = method,
              httpheader    = c(Expect        = "",
                                Authorization = GenerateOauthHeader(request_params, "request")))
  return(res$value())
}
