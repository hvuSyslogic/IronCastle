namespace org.bouncycastle.est
{
	/// <summary>
	/// TLSUniqueProvider implementation of this can provide the TLS unique value.
	/// </summary>
	public interface TLSUniqueProvider
	{
		/// <summary>
		/// Return true if a TLS unique value should be available.
		/// </summary>
		/// <returns> true if a TLS unique should be available, false otherwise. </returns>
		bool isTLSUniqueAvailable();

		/// <summary>
		/// Return the TLS unique value.
		/// </summary>
		/// <returns> a TLS unique value. </returns>
		byte[] getTLSUnique();
	}

}