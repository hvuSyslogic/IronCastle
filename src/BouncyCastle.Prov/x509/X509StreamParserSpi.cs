namespace org.bouncycastle.x509
{
	using StreamParsingException = org.bouncycastle.x509.util.StreamParsingException;


	/// <summary>
	/// This abstract class defines the service provider interface (SPI) for
	/// X509StreamParser.
	/// </summary>
	/// <seealso cref= org.bouncycastle.x509.X509StreamParser
	///  </seealso>
	public abstract class X509StreamParserSpi
	{
		/// <summary>
		/// Initializes this stream parser with the input stream.
		/// </summary>
		/// <param name="in"> The input stream. </param>
		public abstract void engineInit(InputStream @in);

		/// <summary>
		/// Returns the next X.509 object of the type of this SPI from the given
		/// input stream.
		/// </summary>
		/// <returns> the next X.509 object in the stream or <code>null</code> if the
		///         end of the stream is reached. </returns>
		/// <exception cref="StreamParsingException">
		///                if the object cannot be created from input stream. </exception>
		public abstract object engineRead();

		/// <summary>
		/// Returns all X.509 objects of the type of this SPI from
		/// the given input stream.
		/// </summary>
		/// <returns> A collection of all X.509 objects in the input stream or
		///         <code>null</code> if the end of the stream is reached. </returns>
		/// <exception cref="StreamParsingException">
		///                if an object cannot be created from input stream. </exception>
		public abstract Collection engineReadAll();
	}

}