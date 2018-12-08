namespace org.bouncycastle.mime
{

	/// <summary>
	/// Base interface for a MIME parser listener.
	/// </summary>
	public interface MimeParserListener
	{
		/// <summary>
		/// Create an appropriate context object for the MIME object represented by headers.
		/// </summary>
		/// <param name="parserContext"> context object for the current parser. </param>
		/// <param name="headers"> MIME headers for the object that has been discovered. </param>
		/// <returns> a MimeContext </returns>
		MimeContext createContext(MimeParserContext parserContext, Headers headers);

		/// <summary>
		/// Signal that a MIME object has been discovered.
		/// </summary>
		/// <param name="parserContext"> context object for the current parser. </param>
		/// <param name="headers"> headers for the MIME object. </param>
		/// <param name="inputStream"> input stream representing its content. </param>
		/// <exception cref="IOException"> in case of a parsing/processing error. </exception>
		void @object(MimeParserContext parserContext, Headers headers, InputStream inputStream);
	}

}