namespace javax.crypto
{

	/// <summary>
	/// This exception is thrown when the length of data provided to a block
	/// cipher is incorrect, i.e., does not match the block size of the cipher.
	/// 
	/// </summary>
	public class IllegalBlockSizeException : GeneralSecurityException
	{
		private const long serialVersionUID = -1965144811953540392L;

		/// <summary>
		/// Constructs an IllegalBlockSizeException with no detail message.
		/// (A detail message is a String that describes this particular
		/// exception.)
		/// </summary>
		public IllegalBlockSizeException()
		{
		}

		/// <summary>
		/// Constructs an IllegalBlockSizeException with the specified
		/// detail message. (A detail message is a String that describes
		/// this particular exception.)
		/// </summary>
		/// <param name="msg"> the detail message. </param>
		public IllegalBlockSizeException(string msg) : base(msg)
		{
		}
	}

}