namespace javax.crypto
{

	/// <summary>
	/// This exception is thrown when a particular padding mechanism is
	/// requested but is not available in the environment.
	/// </summary>
	public class NoSuchPaddingException : GeneralSecurityException
	{
		private const long serialVersionUID = -4572885201200175466L;

		/// <summary>
		/// Constructs a NoSuchPaddingException with no detail
		/// message. A detail message is a String that describes this
		/// particular exception.
		/// </summary>
		public NoSuchPaddingException()
		{
		}

		/// <summary>
		/// Constructs a NoSuchPaddingException with the specified
		/// detail message. A detail message is a String that describes
		/// this particular exception, which may, for example, specify which
		/// algorithm is not available.
		/// </summary>
		/// <param name="msg"> - the detail message. </param>
		public NoSuchPaddingException(string msg) : base(msg)
		{
		}
	}

}