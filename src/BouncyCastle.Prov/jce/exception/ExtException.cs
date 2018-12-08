using System;

namespace org.bouncycastle.jce.exception
{
	/// 
	/// <summary>
	/// This is an extended exception. Java before version 1.4 did not offer the
	/// possibility the attach a cause to an exception. The cause of an exception is
	/// the <code>Throwable</code> object which was thrown and caused the
	/// exception. This interface must be implemented by all exceptions to accomplish
	/// this additional functionality.
	/// 
	/// </summary>
	public interface ExtException
	{

		/// <summary>
		/// Returns the cause of the exception.
		/// </summary>
		/// <returns> The cause of the exception. </returns>
		Exception getCause();
	}

}