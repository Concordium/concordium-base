using System;

namespace IdissLib
{

    /// An Exception to be thrown in case of validation failure of a request.
    public class RequestValidationException : Exception
    {
        public RequestValidationException(string message) : base(message)
        {
        }
    }

    /// An Exception to be thrown in case that identity creation does not succeed.
    public class IdentityCreationException : Exception
    {
        public IdentityCreationException(string message) : base(message)
        {
        }
    }
}