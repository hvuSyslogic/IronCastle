using org.bouncycastle.Port;

namespace org.bouncycastle.util
{
	/// <summary>
	/// Exception to be thrown on a failure to reset an object implementing Memoable.
	/// <para>
	/// The exception extends ClassCastException to enable users to have a single handling case,
	/// only introducing specific handling of this one if required.
	/// </para>
	/// </summary>
	public class MemoableResetException : ClassCastException
	{
		/// <summary>
		/// Basic Constructor.
		/// </summary>
		/// <param name="msg"> message to be associated with this exception. </param>
		public MemoableResetException(string msg) : base(msg)
		{
		}
	}

}