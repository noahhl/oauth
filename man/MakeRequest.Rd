\name{MakeRequest}
\alias{MakeRequest}
\title{Make request via oauth 1.0}
\description{Make a request for a protected resource using credentials resulting from Authorize() or LoadCredentials().}
\usage{MakeRequest(params, resource, method, request=NULL, noisy=FALSE)}
\arguments{
  \item{params}{the parameters of the service and the user, resulting from Authorize() or LoadCredentials()}
  \item{resource}{the URL of the resource you are trying to access. If this is a request in which you would pass request parameters (e.g., <code>?search=abcdefg</code>), do not include those parameters in the resource URL.}
  \item{method}{one of "GET", "POST", "PUT", or "DELETE"}
  \item{request}{any request parameters provided as a named character vector (e.g., c(search="Test", since="yesterday")). may be null.}
  \item{noisy}{binary setting to enable verbosity in handshaking}
}
\seealso{Authorize}
\examples{
  \dontrun{MakeRequest(params, "http://api.twitter.com/1/account/verify_credentials.json", "GET")}
  \dontrun{MakeRequest(params, "http://api.twitter.com/1/statuses/update.json", "POST", request=c(status="#rstats is my hero."))}
}
