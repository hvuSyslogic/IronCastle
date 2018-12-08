namespace org.bouncycastle.mime
{
	/// <summary>
	/// Base interface for a MIME parser context.
	/// </summary>
	public interface MimeParserContext
	{
		/// <summary>
		/// Return the default value for Content-Transfer-Encoding for data we are parsing.
		/// </summary>
		/// <returns> the default Content-Transfer-Encoding. </returns>
		string getDefaultContentTransferEncoding();
	}

}