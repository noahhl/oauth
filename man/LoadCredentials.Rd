\name{LoadCredentials}
\alias{LoadCredentials}
\title{Load previously saved credentials}
\description{Loads previously saved credentials resulting from the Authorize() command.}
\usage{LoadCredentials(site=NULL, file=NULL)}
\arguments{
  \item{site}{the site name extracted from the server params if Authorize() was run without a file specified.}
  \item{file}{file specified in Authorize() to save parameters to}
}
\seealso{Authorize}
\examples{
  LoadCredentials(site="api.twitter")
  LoadCredentials(file="~/mycredentials")
}

