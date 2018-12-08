namespace org.bouncycastle.mime
{

	/// <summary>
	/// Base interface for a MIME parser.
	/// </summary>
	public interface MimeParser
	{
		/// <summary>
		/// Trigger the start of parsing.
		/// </summary>
		/// <param name="listener"> callback to be signalled as each MIME object is identified. </param>
		/// <exception cref="IOException"> on a parsing/IO exception. </exception>
		void parse(MimeParserListener listener);
	}
}