namespace org.bouncycastle.est
{

	/// <summary>
	/// Interface for a Source which can only produce up to a certain number of bytes.
	/// </summary>
	public interface LimitedSource
	{
		/// <summary>
		/// Return the maximum number of bytes available from this source.
		/// </summary>
		/// <returns> the max bytes this source can produce. </returns>
		long? getAbsoluteReadLimit();
	}

}