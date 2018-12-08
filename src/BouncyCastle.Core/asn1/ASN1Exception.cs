using System;
using System.IO;

namespace org.bouncycastle.asn1
{

	/// <summary>
	/// Exception thrown in cases of corrupted or unexpected data in a stream.
	/// </summary>
	public class ASN1Exception : IOException
	{
		private Exception cause;

		/// <summary>
		/// Base constructor
		/// </summary>
		/// <param name="message"> a message concerning the exception. </param>
		public ASN1Exception(string message) : base(message)
		{
		}

		/// <summary>
		/// Constructor when this exception is due to another one.
		/// </summary>
		/// <param name="message"> a message concerning the exception. </param>
		/// <param name="cause"> the exception that caused this exception to be thrown. </param>
		public ASN1Exception(string message, Exception cause) : base(message)
		{
			this.cause = cause;
		}

		/// <summary>
		/// Return the underlying cause of this exception, if any.
		/// </summary>
		/// <returns> the exception causing this one, null if there isn't one. </returns>
		public virtual Exception getCause()
		{
			return cause;
		}
	}

}