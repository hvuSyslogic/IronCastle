namespace javax.crypto
{

	/// <summary>
	/// This exception is thrown when a particular padding mechanism is
	/// expected for the input data but the data is not padded properly
	/// 
	/// </summary>
	public class BadPaddingException : GeneralSecurityException
	{
		private const long serialVersionUID = -5315033893984728443L;

		/// <summary>
		/// Constructs a BadPaddingException with no detail
		/// message. A detail message is a String that describes this
		/// particular exception.
		/// </summary>
		public BadPaddingException()
		{
		}

		/// <summary>
		/// Constructs a BadPaddingException with the specified
		/// detail message. A detail message is a String that describes
		/// this particular exception, which may, for example, specify which
		/// algorithm is not available.
		/// </summary>
		/// <param name="msg"> the detail message. </param>
		public BadPaddingException(string msg) : base(msg)
		{
		}
	}

}