using System.IO;

namespace org.bouncycastle.util.io
{

	/// <summary>
	/// Exception thrown when too much data is written to an InputStream
	/// </summary>
	public class StreamOverflowException : IOException
	{
		public StreamOverflowException(string msg) : base(msg)
		{
		}
	}

}