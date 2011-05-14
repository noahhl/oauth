\name{Authorize}
\alias{Authorize}
\title{Authorize via oauth 1.0}
\description{Conduct authorization "handshake" with a server specified in params. Directs user to authenticate, provide return parameter, and optionally saves credentials for future use.}
\usage{params <- Authorize(params, noisy=F, save=T, file=NULL)}
\arguments{
  \item{params}{the parameters of the service and the user, specified as follows:}

  \code{params <- list(oauth_consumer_key = "B2QJkcSYdARDJ10Gjo2kNw", 

              oauth_consumer_secret = "WJPF3SENJdk3ACSDF1OJfVJ5EDI3BkYbEQASDFSFA", 

              oauth_callback="http://somedomain.com",

              oauth_signature_method = "HMAC-SHA1",

              oauth_version="1.0", 

              server = list(
                            #To get request token
                            
                            initiate = "https://api.twitter.com/oauth/request_token",
                            #For user authentication
                            
                            auth = "https://api.twitter.com/oauth/authorize",
                            
                            #For access token
                            
                            token = "https://api.twitter.com/oauth/access_token"))
                            }
  \item{noisy}{binary setting to enable verbosity in handshaking}
  \item{save}{binary setting to save credentials to a local file for future use}
  \item{file}{file to save parameters to. if unspecified, a file name will be extracted from server params}
}
\seealso{MakeRequest}
\examples{
  \dontrun{params <- Authorize(params)}
}
