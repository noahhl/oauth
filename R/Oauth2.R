Oauth2Authorize <- function(params, noisy=F, save=T, file=NULL, refresh=F) {
  require(RJSONIO)
  if(refresh) {
    cat("Refreshing your token.\n")
    resp <- fromJSON(rawToChar(postForm(params$token_uri, .params=list(client_id = params$client_id, client_secret = params$client_secret, refresh_token=params$refresh_token, type="refresh", redirect_uri=params$redirect_uri))))
    params$access_token = resp$access_token
  } else {
    url = paste(params$request_uri, "?type=", params$type, "&redirect_uri=", URLencode(params$redirect_uri, T), "&client_id=", params$client_id, sep="")
    cat("Go to: ", url, "(going to try to take you there now)\n")
    browseURL(url)
    cat("\n\nEnter the code received there:\n")
    params$response_code <- readline()
    params <- c(params, fromJSON(rawToChar(postForm(params$token_uri, .params=list(client_id = params$client_id, client_secret = params$client_secret, code=params$response_code, type=params$type, redirect_uri=params$redirect_uri)))))    
  }
  if(save) {
    site <- paste(sub("https://|http://", "", strsplit(params$request_uri, "\\.")[[1]])[1:(grep("/", sub("https://|http://", "", strsplit(params$request_uri, "\\.")[[1]]))[1]-1)], collapse=".")
    
    if(is.null(file)) {
      file=paste(".oauthparams_", site, ".Rdata", sep="")
    }
    save(params, file=file)
  }
  return(params)
} 


Oauth2MakeRequest <- function(params, resource, method, request=NULL, noisy=FALSE) {
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
  curlPerform(url           = uri,
              verbose       = noisy,
              writefunction = res$update,
              customrequest = method,
              httpheader    = c(Expect        = "",
                                Authorization = paste("Token token=", params$access_token, sep="")))
  return(res$value())
}
