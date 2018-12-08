namespace javax.crypto
{

	/// <summary>
	/// This exception is thrown when an output buffer provided by the user
	/// is too short to hold the operation result.
	/// </summary>
	public class ShortBufferException : GeneralSecurityException
	{
		private const long serialVersionUID = 8427718640832943747L;

		/// <summary>
		/// Constructs a ShortBufferException with no detail
		/// message. A detail message is a String that describes this
		/// particular exception.
		/// </summary>
		public ShortBufferException()
		{
		}

		/// <summary>
		/// Constructs a ShortBufferException with the specified
		/// detail message. A detail message is a String that describes
		/// this particular exception, which may, for example, specify which
		/// algorithm is not available.
		/// </summary>
		/// <param name="msg"> the detail message. </param>
		public ShortBufferException(string msg) : base(msg)
		{
		}
	}

}