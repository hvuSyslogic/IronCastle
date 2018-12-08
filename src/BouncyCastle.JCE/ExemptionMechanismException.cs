namespace javax.crypto
{

	/// <summary>
	/// This is the generic ExemptionMechanism exception.
	/// 
	/// </summary>
	public class ExemptionMechanismException : GeneralSecurityException
	{
		private const long serialVersionUID = 1572699429277957109L;

		/// <summary>
		/// Constructs a ExemptionMechanismException with no detailed message.
		/// (A detailed message is a String that describes this particular exception.)
		/// </summary>
		public ExemptionMechanismException()
		{
		}

		/// <summary>
		/// Constructs a ExemptionMechanismException with the specified
		/// detailed message. (A detailed message is a String that describes
		/// this particular exception.)
		/// </summary>
		/// <param name="msg"> the detailed message. </param>
		public ExemptionMechanismException(string msg) : base(msg)
		{
		}
	}

}