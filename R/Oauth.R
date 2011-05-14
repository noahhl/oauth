LoadCredentials <- function(site=NULL, file=NULL) {
  if(is.null(site) && is.null(file))
    stop("You need to provide some information to identify the credentials you'd like to load.")

  if(is.null(file)) {
    file = file=paste(".oauthparams_", site, ".Rdata", sep="")
  }
  load(file, envir = .GlobalEnv)
}

