#require("Crypto.R")

SignForOauth <- function(uri, request_method, request_params, consumer_secret, secret="") {
    key <-paste(URLencode(consumer_secret), URLencode(secret), sep="&")
    msg <- GenerateSignatureBaseString(uri, request_method, request_params)
    if(request_params$oauth_signature_method == "HMAC-SHA1") {
     signature <- base64(HmacSha1(key, msg))[1]
    }
    return(signature)
}

GenerateSignatureBaseString <- function(uri, method, request_params) {
    request_params <- request_params[sort(names(request_params))]
    JoinParams <- function(x) {
      a <- request_params[[x]]
      #Need to double URLencode callback URLs
      if(names(request_params[x]) == "oauth_callback" || substr(names(request_params[x]),1,5)!="oauth") {
        a <- URLencode(a, TRUE) 
      }
        return(paste(names(request_params[x]), a, sep="="))
    }
    request_params.string  <- URLencode(paste((sapply(1:length(request_params), JoinParams)), collapse="&"), TRUE)
    uri            <- URLencode(uri)
    request_method <- toupper(method)
    paste(c(request_method, uri, request_params.string), collapse="&")
}


GenerateOauthHeader <- function(unsort_request_params, use="target") {
  if(use == "target") {
    request_params <- c(unsort_request_params['oauth_nonce'], unsort_request_params['oauth_callback'], unsort_request_params['oauth_signature_method'], unsort_request_params['oauth_timestamp'], unsort_request_params['oauth_consumer_key'], unsort_request_params['oauth_signature'], unsort_request_params['oauth_version'])    
  } else if (use == "auth") {
    request_params <- c(unsort_request_params['oauth_nonce'], unsort_request_params['oauth_signature_method'], unsort_request_params['oauth_timestamp'], unsort_request_params['oauth_consumer_key'], unsort_request_params['oauth_token'], unsort_request_params['oauth_verifier'], unsort_request_params['oauth_signature'], unsort_request_params['oauth_version'])
  }  else if (use == "request") {
    request_params <- c(unsort_request_params['oauth_nonce'], unsort_request_params['oauth_signature_method'], unsort_request_params['oauth_timestamp'], unsort_request_params['oauth_consumer_key'], unsort_request_params['oauth_token'], unsort_request_params['oauth_signature'], unsort_request_params['oauth_version'])
    }
    len  <- length(request_params)
    Joinrequest_params <- function(x) {
        paste(as.character(names(request_params[x])),
              "=", '"',
              URLencode(as.character(request_params[x]), TRUE),
              '"', sep="")
    }
    paste("OAuth", paste(sapply(1:len, Joinrequest_params), collapse=", "))
}

#Override utils::URLencode to uppercase encodings
URLencode <- function (noncoded, reserved=T) {
    OK <- "[^-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.~]"
    x <- strsplit(noncoded, "")[[1L]]
    z <- grep(OK, x)
    if (length(z)) {
        y <- sapply(x[z], function(x) paste("%", toupper(as.character(charToRaw(x))), 
        sep = "", collapse = ""))
        x[z] <- y
    }
    paste(x, collapse = "")
}
