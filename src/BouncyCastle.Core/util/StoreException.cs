using System;
using org.bouncycastle.Port;

namespace org.bouncycastle.util
{
	/// <summary>
	/// Exception thrown if there's an issue doing a match in store.
	/// </summary>
	public class StoreException : RuntimeException
	{
		private Exception _e;

		/// <summary>
		/// Basic Constructor.
		/// </summary>
		/// <param name="msg"> message to be associated with this exception. </param>
		/// <param name="cause"> the throwable that caused this exception to be raised. </param>
		public StoreException(string msg, Exception cause) : base(msg)
		{
			_e = cause;
		}

		public virtual Exception getCause()
		{
			return _e;
		}
	}

}